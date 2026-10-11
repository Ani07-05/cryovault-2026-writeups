#include <stdlib.h>
#include <string.h>
#include <math.h>
#define MAXS 16
/* forward-backward for hidden-age model.
 n steps; nst = cap-1 states (lag = a+2), s[t] symbol, f[t] flip, z[t] in 0..7 (clipped disparity drive).
 C[16] cell probs, H[8]. t0: first step used (needs s[t-lag] available, lag<=nst+1).
 out: n1[16], n0[16] posterior soft counts, returns loglik. segstart: indices where HMM restarts handled by caller (single segment). */
double fb(int n,int nst,const int*s,const int*f,const int*z,const double*C,const double*H,int t0,double*n1,double*n0){
  double *al=(double*)malloc(sizeof(double)*n*MAXS);
  double *sc=(double*)malloc(sizeof(double)*n);
  double a[MAXS],nx[MAXS];
  int i,t,k;
  for(i=0;i<nst;i++)a[i]=0; a[nst-1]=1.0;
  double ll=0;
  for(i=0;i<16;i++){n1[i]=0;n0[i]=0;}
  for(t=t0;t<n;t++){
    memcpy(al+(size_t)t*MAXS,a,sizeof(double)*MAXS);
    double h=H[z[t]];
    for(i=0;i<nst;i++)nx[i]=0;
    for(i=0;i<nst;i++){
      int d=(s[t]-s[t-i-2])&15; double c=C[d];
      int nxt=(i+1<nst)?i+1:nst-1;
      if(f[t]){ nx[0]+=a[i]*c; nx[nxt]+=a[i]*(1-c)*h; }
      else { nx[nxt]+=a[i]*(1-c)*(1-h); }
    }
    double tot=0; for(i=0;i<nst;i++)tot+=nx[i];
    if(tot<1e-300)tot=1e-300;
    sc[t]=tot; ll+=log(tot);
    for(i=0;i<nst;i++)a[i]=nx[i]/tot;
  }
  /* backward */
  double b[MAXS],nb[MAXS];
  for(i=0;i<nst;i++)b[i]=1.0;
  for(t=n-1;t>=t0;t--){
    double h=H[z[t]];
    const double*at=al+(size_t)t*MAXS;
    for(i=0;i<nst;i++){
      int d=(s[t]-s[t-i-2])&15; double c=C[d];
      int nxt=(i+1<nst)?i+1:nst-1;
      double pE,pN; /* joint prob of (E=1,f) and (E=0,f) times beta */
      double w1,w0;
      if(f[t]){ w1=c*b[0]; w0=(1-c)*h*b[nxt]; }
      else { w1=0; w0=(1-c)*(1-h)*b[nxt]; }
      /* posterior weight of (state i, E) at t */
      double g1=at[i]*w1/sc[t], g0=at[i]*w0/sc[t];
      n1[d]+=g1; n0[d]+=g0;
      nb[i]=(w1+w0)/sc[t];
    }
    for(i=0;i<nst;i++)b[i]=nb[i];
  }
  free(al);free(sc);
  return ll;
}
