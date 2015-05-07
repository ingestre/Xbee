#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <termios.h>
#include <dirent.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/stat.h>

int fp;
// FILE *fp;

unsigned char        dirf[256] = "/home/monitor/xb";
int     debug=0;
int     quitcode=0;
FILE    *lf;
int     slf,shf;
unsigned char sl[8];
static int ci=1;

unsigned char cfn[256][64];

void signal_handler(int sig)
{
        switch(sig)
        {
                case SIGTERM:
                        quitcode=sig;
                        break;
                case SIGINT:
                        quitcode=sig;
                        break;
                case SIGQUIT:
                        quitcode=sig;
                        break;
        }
}

printtime()
{
        time_t  timer;
        struct tm*      time_struct;
        timer=time(NULL);
        time_struct=localtime(&timer);
        fprintf(lf,"%02d/%02d/%d %02d:%02d:%02d ",time_struct->tm_mday, time_struct->tm_mon + 1,
                time_struct->tm_year + 1900, time_struct->tm_hour,time_struct->tm_min,time_struct->tm_sec);
}

unsigned char readescaped()
{
        unsigned char   a;
        int r;

        r=0;
        do {
                r=read(fp,&a,1);
                // r=fread(&a,1,1,fp);
        } while (r<1);
        if (a==125)
        {
                r=0;
                do {
                        r=read(fp,&a,1);
                        // r=fread(&a,1,1,fp);
                } while (r<1);
                a ^= 0x20;
        }
        return(a);
}

int getframe( unsigned char* store )
{
        unsigned char   a,b,c,d;
        int     n,s,crc;

        a=0;
        s=0;
        n=0;
        s=read(fp,&a,1);
        // s=fread(&a,1,1,fp);
        if (s==1)
        {
                if (a==0x7e)
                {
                        b=readescaped();
                        c=readescaped();
                        if (debug>=2) { printtime(); fprintf(lf,"<-- 7E %02X %02X",b,c); }
                        n=b*256+c;
                        s=n;
                        // printf("Frame is %d chars long\n",n);
                        crc=0;
                        a=0;
                        while ( s-- > 0 )
                        {
                                store[a]=readescaped(); if (debug>=2) { fprintf(lf," %02X",store[a]); }
                                crc += store[a];
                                // if (a==30) printf("...\n");
                                // if (a<30) printf("%02X ",store[a]);
                                a=a+1;
                        }
                        // printf("\n");
                        crc &= 255;
                        crc=255-crc;
                        d=readescaped(); if (debug>=2) { fprintf(lf," %02X\n",d); fflush(lf); }
                        if ( !(crc==d) )
                        {
                                printtime();
                                fprintf(lf,"Frame checksum wrong. Expected %X, got %X\n",crc,d);
                                fflush(lf);
                                n=0;
                        }
                }
                else
                {
                        printtime();
                        fprintf(lf,"OOB data %02X - Performing reset on coordinator module\n",a);
      localcommand(ci++,"FR",0,"");
                        fflush(lf);
                }
        }
        return(n);
}

int escapebuff(int bs,unsigned char* ob, unsigned char* eb)
{
        int i,j;

        j=1;
        eb[0]=ob[0];
        for (i=1;i<bs;i++)
        {
                switch (ob[i]) {
                case 0x13:
                        eb[j]=125;
                        eb[j+1]=ob[i]^32;
                        j=j+2;
                        break;
                case 0x11:
                        eb[j]=125;
                        eb[j+1]=ob[i]^32;
                        j=j+2;
                        break;
                case 0x7d:
                        eb[j]=125;
                        eb[j+1]=ob[i]^32;
                        j=j+2;
                        break;
                case 0x7e:
                        eb[j]=125;
                        eb[j+1]=ob[i]^32;
                        j=j+2;
                        break;
                default:
                        eb[j]=ob[i];
                        j=j+1;
                }
        }
        return(j);
}

pframe(int cnt,unsigned char* bufp)
{
        int k;

        for (k=0;k<cnt;k++) fprintf(lf,"%02X ",bufp[k]);
        fprintf(lf,"\n");
}

localcommand(int framenum,unsigned char* cmnd,int pcnt, unsigned char* parr)
{
        unsigned char obuff[32];
        unsigned char ebuff[64];
        int crc,j,w;
        obuff[0]=0x7e;
        obuff[1]=0x00;
        obuff[2]=0x04+pcnt;
        obuff[3]=0x08;
        obuff[4]=(framenum & 255);;
        obuff[5]=cmnd[0];
        obuff[6]=cmnd[1];
        for (j=0;j<pcnt;j++) obuff[7+j]=parr[j];
        crc=0;
        for (j=3;j<7+pcnt;j++) { crc+=obuff[j]; crc&=255; }
        obuff[7+pcnt]=255-crc;

        j=escapebuff(8+pcnt,obuff,ebuff);
        if (debug>=2) { printtime(); fprintf(lf,"--> "); pframe(j,ebuff); fflush(lf); }
        w=write(fp,ebuff,j);
        if (w!=j) { printtime(); fprintf(lf,"Error writing %d bytes of data - write return code was %d\n",j,w); fflush(lf); }
        // fwrite(ebuff,1,j,fp);
}

remotecommand(int framenum,unsigned char* dest, unsigned char* cmnd,int pcnt, unsigned char* parr)
{
        unsigned char obuff[32];
        unsigned char ebuff[64];
        int crc,j;
        obuff[0]=0x7e;
        obuff[1]=0x00;
        obuff[2]=0x0F+pcnt;
        obuff[3]=0x17;
        obuff[4]=(framenum & 255);
        obuff[5]=dest[0];
        obuff[6]=dest[1];
        obuff[7]=dest[2];
        obuff[8]=dest[3];
        obuff[9]=dest[4];
        obuff[10]=dest[5];
        obuff[11]=dest[6];
        obuff[12]=dest[7];
        obuff[13]=0xFF;
        obuff[14]=0xFE;
        obuff[15]=0x02;
        obuff[16]=cmnd[0];
        obuff[17]=cmnd[1];
        for (j=0;j<pcnt;j++) obuff[18+j]=parr[j];
        crc=0;
        for (j=3;j<18+pcnt;j++)
        {
                crc+=obuff[j];
                crc&=255;
        }
        obuff[18+pcnt]=255-crc;
        j=escapebuff(19+pcnt,obuff,ebuff);
        if (debug>=2) { printtime(); fprintf(lf,"--> "); pframe(j,ebuff); fflush(lf); }
        write(fp,ebuff,j);
        // fwrite(ebuff,1,j,fp);
}

int processfile( unsigned char *fn, unsigned char *d )
{
        int val,sc,rc,i,bc;
        unsigned char rpb[8];
        unsigned char pb[8];
        rc=1;
        if (ci>255) ci=1;
        printtime(); fprintf(lf,"Command (%02X)= %c%c",ci,fn[18],fn[19]);
        bc=0;
        if (fn[20]==0x00)
        {
                fprintf(lf,"\n");
                fflush(lf);
                strncpy(cfn[ci],fn,63);cfn[ci][63]=0x00;
                if (d[0]==sl[0] && d[1]==sl[1] &&d[2]==sl[2] && d[3]==sl[3] &&
                    d[4]==sl[4] && d[5]==sl[5] &&d[6]==sl[6] && d[7]==sl[7]) localcommand(ci++,fn+18,0,fn+20);
                else remotecommand(ci++,d,fn+18,0,fn+20);
        }
        else
        {
                sc=sscanf(fn+20,"%X",&val);
                if (sc==1)
                {
                        fprintf(lf,", Parameter=%X - ",val);
                        if (val==0)
                        {
                          rpb[0]=0;
                          bc=1;
                        }
                        else
                        {
                          for (i=0;val!=0;i++)
                          {
                            rpb[i]=val & 255;
                            val=val/256;
                          }
                          bc=i;
                        }
                        for (i=0;i<bc;i++)
                        {
                                pb[i]=rpb[bc-1-i];
                        }
                        pframe(bc,pb);
                        fflush(lf);
                        strncpy(cfn[ci],fn,63);cfn[ci][63]=0x00;
                        if (d[0]==sl[0] && d[1]==sl[1] &&d[2]==sl[2] && d[3]==sl[3] &&
                            d[4]==sl[4] && d[5]==sl[5] &&d[6]==sl[6] && d[7]==sl[7]) localcommand(ci++,fn+18,bc,pb);
                        else remotecommand(ci++,d,fn+18,bc,pb);
                }
                else
                {
                        fprintf(lf,"Bad parameter '%s'\n",fn+20);
                        fflush(lf);
                        rc=0;
                }
        }
        return(rc);
}

off_t get_file_size (const char * file_name)
{
        struct stat sb;
        if (stat (file_name, & sb) != 0)
        {
                printtime();
                fprintf (lf, "'stat' failed for '%s': %s.\n", file_name, strerror (errno));
                fflush(lf);
        }
        return sb.st_size;
}

int transmitdata( int framenum, unsigned char *fn, unsigned char *d )
{
        int rc,i,j,w,crc;
        unsigned char fpath[80];
        unsigned char fdata[100];
        off_t   fsize;
        FILE    *tf;
        unsigned char obuff[256];
        unsigned char ebuff[512];

        rc=0;
        sprintf(fpath,"%s/%s",dirf,fn);
        printtime(); fprintf(lf,"Processing transmit file %s \n",fpath); fflush(lf);
        if ((fsize=get_file_size(fpath)) > 100)
        {
                printtime(); fprintf(lf,"Can't send more than 100 bytes - Ignoring transmit request\n"); fflush(lf);
                remove(fpath);
        }
        else
        {
                if ((tf=fopen(fpath,"rb"))==NULL)
                {
                        printtime(); fprintf(lf,"Couldn't open %s for binary reading - Ignoring transmit request\n",fpath); fflush(lf);
                        remove(fpath);
                }
                else
                {
                        if (fread(fdata,1,fsize,tf) != fsize)
                        {
                                printtime(); fprintf(lf,"Error reading %d bytes from %s - Ignoring transmit request\n",fsize,fpath); fflush(lf);
                                remove(fpath);
                        }
                        else
                        {
                                printtime(); fprintf(lf,"Sending %d bytes to module\n",fsize); fflush(lf);
                                obuff[0]=0x7e;
                                obuff[1]=0x00;
                                obuff[2]=(fsize+11) & 255;
                                obuff[3]=0x00;
                                /* Next byte is the frame number */
                                obuff[4]=framenum;
                                obuff[5]=d[0];
                                obuff[6]=d[1];
                                obuff[7]=d[2];
                                obuff[8]=d[3];
                                obuff[9]=d[4];
                                obuff[10]=d[5];
                                obuff[11]=d[6];
                                obuff[12]=d[7];
        obuff[13]=0;
                                for (i=0;i<fsize;i++) obuff[14+i]=fdata[i];
                                crc=0;
                                for (j=3;j<14+fsize;j++)
                                {
                                        crc+=obuff[j];
                                        crc&=255;
                                }
                                obuff[j]=255-crc;
                                if (debug>=1) { printtime(); fprintf(lf,"--> "); pframe(j+1,obuff); fflush(lf); }
                                j=escapebuff(j+1,obuff,ebuff);
                                w=write(fp,ebuff,j);
                                if (debug>=1) { printtime(); fprintf(lf,"--> "); pframe(j,ebuff); fflush(lf); }
                                if (w!=j) { printtime(); fprintf(lf,"Error writing %d bytes of data - write return code was %d\n",j,w); fflush(lf); }
                        }
                }
        }
        return(rc);
}

int checkfortransmitdata()
{
        DIR     *dirp;
        struct  dirent *dp;
        unsigned char sbuff[20];
        unsigned char rsn[8];
        int i,rc;

        rc=0;
        if ((dirp = opendir(dirf)) == NULL)
        {
                printtime();
                fprintf(lf,"Couldn't open the %s directory\n",dirf);
                fflush(lf);
        }
        else
        {
                for ( dp=readdir(dirp) ; dp!=NULL; dp=readdir(dirp) )
                {
                        if (dp->d_name[0]=='T')
                        {
                                i=sscanf(dp->d_name,"T%02X%02X%02X%02X%02X%02X%02X%02X",&rsn[0],
                                        &rsn[1],&rsn[2],&rsn[3],&rsn[4],&rsn[5],&rsn[6],&rsn[7]);
                                if (i==8)
                                {
                                  if (ci>255) ci=1;
                                  strncpy(cfn[ci],dp->d_name,63);cfn[ci][63]=0x00;
                                        rc += transmitdata(ci++,dp->d_name,rsn);
                                }
                        }
                }
        }
        closedir(dirp);
        return(rc);
}

int checkforqueuedcommands( unsigned char *sn )
{
        DIR     *dirp;
        struct  dirent *dp;
        unsigned char sbuff[20];
        unsigned char rsn[8];
        int     i,match,rc,slen;
        rc=0;
        if (sn != NULL)
        {
                sprintf(sbuff,"Q%02X%02X%02X%02X%02X%02X%02X%02X",sn[0],
                        sn[1],sn[2],sn[3],sn[4],sn[5],sn[6],sn[7]);
                slen=17;
        }
        else
        {
                sbuff[0]='I';
                slen=1;
        }
        if ((dirp = opendir(dirf)) == NULL)
        {
                printtime();
                fprintf(lf,"Couldn't open the %s directory\n",dirf);
                fflush(lf);
        }
        else
        {
                for ( dp=readdir(dirp) ; dp!=NULL; dp=readdir(dirp) )
                {
                        match=0;
                        for (i=0;i<slen;i++)
                        {
                                if (sbuff[i] != dp->d_name[i])
                                {
                                        match=-1;
                                        i=slen+1;
                                }
                        }
                        if (match==0)
                        {
                                if (sn == NULL)
                                {
                                        i=sscanf(dp->d_name,"I%02X%02X%02X%02X%02X%02X%02X%02X",&rsn[0],
                                                &rsn[1],&rsn[2],&rsn[3],&rsn[4],&rsn[5],&rsn[6],&rsn[7]);
                                        if (i==8) rc += processfile(dp->d_name,rsn);
                                }
                                else rc += processfile(dp->d_name,sn);
                        }

                }
        }
        closedir(dirp);
        return(rc);
}


remoteresponse64( int i, unsigned char *fr )
{
        int j,df;
        unsigned char rmfb[128];
        unsigned char mvfb[128];
        printtime();
        df=fr[1];
        fprintf(lf,"%02X%02X%02X%02X%02X%02X%02X%02X (%02X) responded to ",
                fr[2],fr[3],fr[4],fr[5],fr[6],fr[7],fr[8],fr[9],df);
        fprintf(lf,"%c%c command with ",fr[12],fr[13]);
        switch (fr[14]) {
                case 0x00:
                        fprintf(lf,"OK ");
                        if (strlen(cfn[df]) != 0)
                        {
                                sprintf(rmfb,"%s/%s",dirf,cfn[df]);
                                remove(rmfb);
                                cfn[df][0]=0x00;
                        }
                        for (j=15;j<i;j++) fprintf(lf,"%02X",fr[j]);
                        break;
                case 0x01:
                        fprintf(lf,"ERROR ");
                        break;
                case 0x02:
                        fprintf(lf,"BADCOMMAND ");
                        break;
                case 0x03:
                        fprintf(lf,"BADPARAMETER ");
                        break;
                case 0x04:
                        fprintf(lf,"NORESPONSE ");
                        if (strlen(cfn[df]) != 0)
                        {
                                sprintf(rmfb,"%s/%s",dirf,cfn[df]);
                                sprintf(mvfb,"%s/Q%s",dirf, &(cfn[df][1]));
                                rename(rmfb,mvfb);
                                cfn[df][0]=0x00;
                        }
                        break;
                default:
                        fprintf(lf,"code %d ",fr[14]);
        }
        fprintf(lf,"\n");
        fflush(lf);
  if (fr[12]=='I' && fr[13]=='S' && fr[14]==0x00)
  {
    unsigned char cbuff[128];
    cbuff[0]=0x82;
    for (j=0;j<8;j++) cbuff[1+j]=fr[2+j];
    cbuff[9]=0x20; cbuff[10]=0x00;
    for (j=15;j<i;j++) cbuff[j-4]=fr[j];
    printtime(); fprintf(lf,"DIO frame composed "); pframe(j-3,cbuff); fflush(lf);
    processwakeup64(j-3,cbuff);
  }
}

localtxresponse( int i, unsigned char *fr )
{
        int df;
        unsigned char rmfb[128];

        df=fr[1];
  printtime(); fprintf(lf,"%02X%02X%02X%02X%02X%02X%02X%02X (%02X) responded to TX request with ",
                             sl[0],sl[1],sl[2],sl[3],sl[4],sl[5],sl[6],sl[7],df);
        switch (fr[2])
        {
                case 0x00:
                        fprintf(lf,"OK\n");
                        if (strlen(cfn[df]) != 0)
                        {
                                sprintf(rmfb,"%s/%s",dirf,cfn[df]);
                                remove(rmfb);
                                cfn[df][0]=0x00;
                        }
                        break;
                case 0x01:
                        fprintf(lf,"NOACK\n");
                        if (strlen(cfn[df]) != 0)
                        {
                                sprintf(rmfb,"%s/%s",dirf,cfn[df]);
                                remove(rmfb);
                                cfn[df][0]=0x00;
                        }
                        break;
                case 0x02:
                        fprintf(lf,"CCAFAILURE\n");
                        if (strlen(cfn[df]) != 0)
                        {
                                sprintf(rmfb,"%s/%s",dirf,cfn[df]);
                                remove(rmfb);
                                cfn[df][0]=0x00;
                        }
                        break;
                case 0x03:
                        fprintf(lf,"PURGED\n");
                        if (strlen(cfn[df]) != 0)
                        {
                                sprintf(rmfb,"%s/%s",dirf,cfn[df]);
                                remove(rmfb);
                                cfn[df][0]=0x00;
                        }
                        break;
        }
        fflush(lf);
}

localresponse( int i, unsigned char *fr )
{
        int df,j;
        unsigned char rmfb[128];

        df=fr[1];
        printtime(); fprintf(lf,"%02X%02X%02X%02X%02X%02X%02X%02X (%02X) responded to ",
                             sl[0],sl[1],sl[2],sl[3],sl[4],sl[5],sl[6],sl[7],df);
        fprintf(lf,"%c%c command with ",fr[2],fr[3]);
        switch (fr[4])
        {
          case 0x00:
            fprintf(lf,"OK ");
            if (strlen(cfn[df]) != 0)
            {
              sprintf(rmfb,"%s/%s",dirf,cfn[df]);
              remove(rmfb);
              cfn[df][0]=0x00;
            }
            for (j=5;j<i;j++) fprintf(lf,"%02X",fr[j]);
            break;
          case 0x01:
            fprintf(lf,"ERROR ");
            break;
          case 0x02:
            fprintf(lf,"BADCOMMAND ");
            break;
          case 0x03:
            fprintf(lf,"BADPARAMETER ");
            break;
          default:
            fprintf(lf,"code %d ",fr[4]);
        }
        fprintf(lf,"\n");
        fflush(lf);

        if (i==9)
        {
          if (fr[0]==0x88 && fr[1]==0x01 && fr[2]==0x53 && fr[3]==0x4C && fr[4]==0x00)
          {
            sl[4]=fr[5]; sl[5]=fr[6]; sl[6]=fr[7]; sl[7]=fr[8]; slf=1;
          }
          if (fr[0]==0x88 && fr[1]==0x02 && fr[2]==0x53 && fr[3]==0x48 && fr[4]==0x00)
          {
            sl[0]=fr[5]; sl[1]=fr[6]; sl[2]=fr[7]; sl[3]=fr[8]; shf=1;
            printtime(); fprintf(lf,"Established communication with co-ordinator Xbee - Serial = ");
            fprintf(lf,"%02X%02X%02X%02X%02X%02X%02X%02X\n",sl[0],sl[1],sl[2],sl[3],sl[4],sl[5],sl[6],sl[7]);
            fflush(lf);
          }
        }

}

processwakeup16( int i, unsigned char *fr )
{
  int j;
  unsigned char cbuff[128];
  if (fr[1]==0 && fr[2]==0)
  {
    cbuff[0]=0x82;
    for (j=0;j<8;j++) cbuff[j+1]=sl[j];
    for (j=3;j<i;j++) cbuff[j+6]=fr[j];
    processwakeup64(i+6,cbuff);
  }
}

processwakeup64( int i, unsigned char *fr )
{
        int j;
        if (fr[11]==0x01)
        {
                        FILE *of;
                        unsigned char   fn[64];
                        sprintf(fn,"%s/S%02X%02X%02X%02X%02X%02X%02X%02X", dirf,
                                fr[1],fr[2],fr[3],fr[4],fr[5],fr[6],fr[7],fr[8]);
                        of = fopen(fn,"a");
                        if (of==NULL)
                        {
                                printtime();
                                fprintf(lf,"Error opening %s for appending\n",fn);
                                fflush(lf);
                        }
                        else
                        {
                                time_t  timer;
                                struct tm*      time_struct;
                                int     val,dio,sa,k;
                                timer=time(NULL);
                                time_struct=localtime(&timer);

                                k=fr[12]*256 + fr[13];
                                fprintf(of,"%02d/%02d/%d %02d:%02d:%02d %d",time_struct->tm_mday,
                                        time_struct->tm_mon + 1, time_struct->tm_year + 1900, time_struct->tm_hour,
                                        time_struct->tm_min,time_struct->tm_sec,k);

                                dio=0;
                                if (fr[13]==0 && (fr[12] & 1)==0)
                                  { sa=14; dio=-1; }
                                else
                                  { sa=16; dio=256 * (fr[14] & 1) + fr[15]; }
                                for (k=1;k<7;k++)
                                {
                                  if ( (fr[12] & (1<<k)) > 0)
                                  {
                                    val=fr[sa]*256 + fr[sa+1];
                                    sa=sa+2;
                                    fprintf(of," %d",val);
                                  }
                                }

                                if (dio>=0)
                                {
                                  int diop;
                                  diop=256 * (fr[12] & 1) + fr[13];
                                  for (k=0;k<9;k++)
                                  {
                                    if ( (diop & (1<<k)) > 0)
                                    {
                                      if ( (dio & (1<<k)) > 0) fprintf(of," 1"); else fprintf(of," 0");
                                    }
                                  }
                                }

                                fprintf(of,"\n");
                                fclose(of);

                                if (debug>=1)
                                {
                                        printtime();
                                        fprintf(lf,"Processed and recorded DIO frame from ");
                                        fprintf(lf,"%02X%02X%02X%02X%02X%02X%02X%02X\n",
                                                fr[1],fr[2],fr[3],fr[4],fr[5],fr[6],fr[7],fr[8]);
                                        fflush(lf);
                                }
                        }
        }
        else
        {
                if (debug>=1)
                {
                        printtime();
                        fprintf(lf,"Error - DIO frame does not contain only a single sample\n");
                        fflush(lf);
                }
        }
        if (slf!=0 && shf!=0)
        {
          j=checkforqueuedcommands(&fr[1]);
          if (j>0 && debug>=1)
          {
            printtime(); fprintf(lf,"Processed %d valid command files\n",j);
            fflush(lf);
          }
        }
}

receivedata64( int i, unsigned char *fr )
{
        FILE *of;
        unsigned char   fn[64];
        int j;

        printtime();
        fprintf(lf,"Received %d bytes of data from ",i-11);
        fprintf(lf,"%02X%02X%02X%02X%02X%02X%02X%02X ",fr[1],fr[2],
                fr[3],fr[4],fr[5],fr[6],fr[7],fr[8]);
        fprintf(lf,"(Sig=-%ddBm, Opt=%d)\n",fr[9],fr[10]);
        fflush(lf);
        sprintf(fn,"%s/R%02X%02X%02X%02X%02X%02X%02X%02X", dirf,
                fr[1],fr[2],fr[3],fr[4],fr[5],fr[6],fr[7],fr[8]);
        of = fopen(fn,"a");
        if (of==NULL)
        {
                printtime();
                fprintf(lf,"Error opening %s for appending\n",fn);
                fflush(lf);
        }
        else
        {
                for (j=11;j<i;j++) fprintf(of,"%c",fr[j]);
                fclose(of);
        }
}

receivedata16( int i, unsigned char *fr )
{
  int j;
  unsigned char cbuff[128];
  if (fr[1]==0 && fr[2]==0)
  {
    cbuff[0]=0x80;
    for (j=0;j<8;j++) cbuff[j+1]=sl[j];
    for (j=3;j<i;j++) cbuff[j+6]=fr[j];
    receivedata64(i+6,cbuff);
  }
}


void daemonize()
{
        int i,lfp;
        char str[10];
        if(getppid()==1) return; /* already a daemon */
        i=fork();
        if (i<0) exit(1); /* fork error */
        if (i>0) exit(0); /* parent exits */
        /* child (daemon) continues */
        setsid(); /* obtain a new process group */
        for (i=getdtablesize();i>=0;--i) close(i); /* close all descriptors */
        i=open("/dev/null",O_RDWR); dup(i); dup(i); /* handle standard I/O */
        umask(027); /* set newly created file permissions */
        chdir("/tmp/"); /* change running directory */
        lfp=open("dm.lock",O_RDWR|O_CREAT,0640);
        if (lfp<0) exit(1); /* can not open */
        if (lockf(lfp,F_TLOCK,0)<0) exit(0); /* can not lock */
        /* first instance continues */
        sprintf(str,"%d\n",getpid());
        write(lfp,str,strlen(str)); /* record pid to lockfile */
        signal(SIGCHLD,SIG_IGN); /* ignore child */
        signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
        signal(SIGTTOU,SIG_IGN);
        signal(SIGTTIN,SIG_IGN);
        signal(SIGHUP,SIG_IGN); /* Ignore  hangup signal */
        signal(SIGTERM,signal_handler); /* catch kill signal */
        signal(SIGINT,signal_handler); /* catch kill signal */
        signal(SIGQUIT,signal_handler); /* catch kill signal */
}

int main( int argc, char *argv[] )
{
        struct termios termOptions;
        fd_set rfds;
        struct timeval tv;
        struct tm* nts;
        FILE    *cf;
        unsigned char        buff[1024];
        unsigned char        port[256] = "/dev/ttyUSB0";
        unsigned char        logn[256] = "/var/log/dm.log";
        int         i,retval;
        time_t lastsamp,clocknow;

        daemonize();

        slf=0;
        shf=0;
        lastsamp=time(NULL);

        if ( !(argc==1) )
        {
                printf("Usage: %s\n",argv[0]);
                return -1;
        }

        cf = fopen("/etc/dm/dm.conf","r");
        if (cf == NULL)
        {
                return -2;
        }
        while (fgets(buff,1024,cf) != NULL)
        {
                unsigned char   setting[256];
                unsigned char   settingvalue[256];
                if (buff[0] != '#')
                {
                        if (sscanf(buff,"%s %s",&setting,&settingvalue) == 2)
                        {
                                if (strcmp(setting,"PORT")==0) sscanf(buff,"%s %s",&setting,&port);
                                if (strcmp(setting,"LOG")==0) sscanf(buff,"%s %s",&setting,&logn);
                                if (strcmp(setting,"DIR")==0) sscanf(buff,"%s %s",&setting,&dirf);
                                if (strcmp(setting,"DEBUG")==0) sscanf(buff,"%s %d",&setting,&debug);
                        }
                        else
                        {
                                printf("Bad config line : %s\n",buff);
                        }
                }
        }
        fclose(cf);

        lf = fopen(logn,"a");
        if (lf == NULL)
        {
                return -3;
        }




        printtime();  fprintf(lf,"--- Starting xbee communication daemon ---\n");
        printtime();  fprintf(lf,"Version = 1.24\n");
        printtime();  fprintf(lf,"Port = %s\n",port);
        printtime();  fprintf(lf,"Logfile = %s\n",logn);
        printtime();  fprintf(lf,"Directory = %s\n",dirf);
        printtime();  fprintf(lf,"Debug = %d\n",debug);
        // printtime();  fprintf(lf,"Sleeping for 5 secs to allow the serial line to stabilise\n");
        // fflush(lf);
        // sleep(5);
        printtime(); fprintf(lf,"Checking clock has been set correctly\n");
        fflush(lf);

        i=0;
        do
        {
                sleep(1); i++;
                clocknow=time(NULL);
                nts=localtime(&clocknow);
        } while ( ((nts->tm_year + 1900) < 2012) && (i<300) );
        if (i<300)
        {
          printtime();  fprintf(lf,"Clock seems good after waiting %d seconds\n",i); fflush(lf);
        }
        else
        {
          printtime();  fprintf(lf,"Waited 300 secs, but clock didn't get set.\n");
          printtime();  fprintf(lf,"Please consider configuring router to send ntp server info with DHCP or ...\n");
          printtime();  fprintf(lf,"set up ntpd daemon with an appropriate time server\n\n");
          fflush(lf);
          return -4;
        }

        // Open the tty:
        fp = open(port, O_RDWR | O_NONBLOCK );
        //fp = open(port, O_RDWR | O_NOCTTY | O_NDELAY);
        if (fp == -1)
        // fp = fopen("/dev/ttyUSB0","r");
        // if (fp == NULL)
        {
                printtime(); fprintf(lf,"Unable to open port %s\n",port); fflush(lf);
                return -1;
        }
        printtime();  fprintf(lf,"Opened %s for reading and writing\n",port);  fflush(lf);

        tcgetattr( fp, &termOptions );
        cfsetispeed( &termOptions, B9600 );
        cfsetospeed( &termOptions, B9600 );
        termOptions.c_cflag &= ~CSIZE;
        termOptions.c_cflag |= CS8;
        termOptions.c_cflag &= ~PARENB;
        termOptions.c_cflag &= ~CSTOPB;

        termOptions.c_iflag &= ~IGNBRK;
        termOptions.c_iflag &= ~BRKINT;
        termOptions.c_iflag &= ~IGNPAR;
        termOptions.c_iflag &= ~PARMRK;
        termOptions.c_iflag &= ~INPCK;
        termOptions.c_iflag &= ~ISTRIP;
        termOptions.c_iflag &= ~INLCR;
        termOptions.c_iflag &= ~IGNCR;
        termOptions.c_iflag &= ~ICRNL;
        termOptions.c_iflag &= ~IXON;
        termOptions.c_iflag &= ~IXOFF;
        termOptions.c_iflag &= ~IUCLC;
        termOptions.c_iflag &= ~IXANY;

        termOptions.c_oflag &= ~OPOST;

        termOptions.c_lflag &= ~ISIG;
        termOptions.c_lflag &= ~ICANON;
        termOptions.c_lflag &= ~XCASE;

        tcsetattr( fp, TCSANOW, &termOptions );
        printtime();  fprintf(lf,"Set %s to 9600,8,n,1\n",port); fflush(lf);

        do {
                FD_ZERO(&rfds);
                FD_SET(fp, &rfds);
                /* Wait up to one seconds. */
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                retval = select(fp+1, &rfds, NULL, NULL, &tv);
                if (retval && quitcode==0)
                {

                        i=getframe( buff );
                        if (i>0)
                        {
                                switch (buff[0]) {
                                        case 0x80:
                                                receivedata64(i,buff);
                                                break;
                                        case 0x81:
                                                printtime();
                                                fprintf(lf,"Received %d bytes of data from ",i-11);
                                                fprintf(lf,"%02X%02X ",buff[1],buff[2]);
                                                fprintf(lf,"(Sig=-%ddBm, Opt=%d)\n",buff[9],buff[10]);
                                                fflush(lf);
                                                break;
                                        case 0x82:
                                                processwakeup64(i,buff);
                                                break;
                                        case 0x83:
                                                processwakeup16(i,buff);
                                                break;
                                        case 0x88:
                                                localresponse(i,buff);
                                                break;
                                        case 0x89:
                                                localtxresponse(i,buff);
                                                break;
                                        case 0x8A:
                                                printtime();
                                                fprintf(lf,"Modem status message %d\n",buff[1]);
                                                fflush(lf);
                                                break;
                                        case 0x97:
                                                remoteresponse64(i,buff);
                                                break;
                                        default:
                                                printtime();
                                                fprintf(lf,"Unknown frame - %02X\n",buff[0]);
                                                printtime();
                                                pframe(i,buff);
                                                fflush(lf);
                                }
                        }
                        else
                        {
                                printtime();
                                fprintf(lf,"Data frame error\n");
                                fflush(lf);
                        }
                }
                else
                {
                        if (slf==0)
                        {
                          localcommand(ci++,"SL",0,"");
                        }
                        else
                        {
                          if (shf==0)
                          {
                            localcommand(ci++,"SH",0,"");
                          }
                          else
                          {
                            checkforqueuedcommands(NULL);
                            checkfortransmitdata();
                            clocknow=time(NULL);
                            if ( (clocknow-lastsamp) >= 60 )
                            {
                              lastsamp=clocknow;
                              // if (debug>=1) { printtime(); fprintf(lf,"Getting sample from master\n"); fflush(lf); }
                              // localcommand(0,"IS",0,"");
                            }
                          }
                        }
                }
        } while (quitcode==0);

        printtime();
        fprintf(lf,"--- Closing down gracefully on receipt of signal %d ---\n\n",quitcode);
        fflush(lf);
        close(fp);
        fclose(lf);
        // fclose(fp);
        remove("/tmp/dm.lock");
        return(0);
}
