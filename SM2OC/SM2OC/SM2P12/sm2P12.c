//
//  sm2P12.c
//  SM2
//
//  Created by 九州云腾 on 2018/4/13.
//  Copyright © 2018年 九州云腾. All rights reserved.
//



#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#ifdef OPENSSL_NO_SM2
//int main(int argc, char **argv)
//{
//    printf("NO SM2 support\n");
//    return 0;
//}
//#else
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>
# include "pkcs12.h"

EVP_PKEY * BaseLoadKey (BIO * bio, char *strPwd)
{
    EVP_PKEY *pkey = NULL;

    PKCS12 *p12 = d2i_PKCS12_bio (bio, NULL);

    PKCS12_parse (p12, strPwd, &pkey, NULL, NULL);
    PKCS12_free (p12);
    p12 = NULL;

    return pkey;
}
int getprivateKeyTxt(const char * p12Path, const char * p12Password, const char *privateKeyTxtPath){

    BIO *in = BIO_new_file(p12Path, "r");
    EVP_PKEY * key = BaseLoadKey(in, (char *)p12Password);

    if (key == NULL) {

        return 0;
    }
    BIO *out = BIO_new_file(privateKeyTxtPath, "w");
    EVP_PKEY_print_private(out, key, 0, NULL);
    if(!out){

        return 0;
    }else{
        BIO_printf(out, "");
        BIO_free(out);
        return 1;
    }

}
