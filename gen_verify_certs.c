// Headers
//
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdbool.h>
#include "Tools/tools.h"
#include "Tools/rsa.h"
#include "Tools/fmea.h"

struct certificate{
    char version[15];
    char serial_num[30];
    char issuer_name[50];
    //period of validity
    int start;
    int end;
    char subject_name[50];
    //algorithm & parameters
    char algorithm[15];
    int pub_key[2];
    //
    int signature;
    

};

// Main function
int main()
{   int time ;
    int menu =0;
 do{
    printf("Would you like to do?\n0.)generate keys\n1.)Create Cert\n2.)Validate Cert integrity\n3.)Populate a Cert Revocation List\n4.)Validate CRL\n5.)Validate certificate trust tree\n6.) Change time\n");
    scanf("%d",&menu);

    if(menu==0)
    create_keys();
    if (menu==1)
    create_cert(); // trust level still needed as exit case for crl tree
    if(menu==2)
    {
        char cert_file[50];
        printf(" PLEASE ENTER THE CERT FILE NAME:\n");
        scanf("%s",cert_file);
        validate_cert(cert_file, time);
    }
    if(menu==3)
        CRL_populate();
    if(menu == 4)
        CRL_validate();
    if(menu == 5)
        tree_validate(time);
    if(menu==6)
    {
        printf("Please enter the new time: \n");
        scanf("%d",&time);
    }
    
 }while(menu!=999);
   
    return 0; 
}
