//
//  SM2_SignIdtoken.m
//  SM2OC
//
//  Created by 九州云腾 on 2018/4/20.
//  Copyright © 2018年 九州云腾. All rights reserved.
//

#import "SM2_SignIdtoken.h"
#import <openssl/sm2.h>
#import "sm2P12.h"
#import "MF_Base64AdditionsSM2.h"
#import "sm2ToOC.h"
#import "NSData+HexString.h"

@implementation SM2_SignIdtoken


+ (NSString *)getSM2_idtokenWithP12Path:(NSString *)p12Path password:(NSString *)p12Password head:(NSDictionary *)header payload:(NSDictionary *)payload{

    NSString *headerString = [SM2_SignIdtoken dictionaryToJson:header];
    NSString *payloadString = [SM2_SignIdtoken dictionaryToJson:payload];
    NSString *str = [NSString stringWithFormat:@"%@.%@",[headerString base64UrlEncodedString],[payloadString base64UrlEncodedString]];
    NSLog(@"前两部分参数 == %@",str);

    NSString *uid = @"1234567812345678";
    EC_GROUP *sm2p256real = new_ec_group(1,
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
                                         "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
                                         "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                                         "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                                         "1");


    NSString *sm2PrivateKey;
    NSString *sm2publicKey;

    NSFileManager *fileManager = [[NSFileManager alloc]init];
    NSString *pathDocuments = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)objectAtIndex:0];
    NSString *createPath = [NSString stringWithFormat:@"%@/Documents/JZYT/",pathDocuments];
    if (![[NSFileManager defaultManager]fileExistsAtPath:createPath]) {

        [fileManager createDirectoryAtPath:createPath withIntermediateDirectories:YES attributes:nil error:nil];

    }else{
    }
    NSString *txtPath = [createPath stringByAppendingString:@"sm2.txt"];
    int ret = getprivateKeyTxt([p12Path cStringUsingEncoding:NSUTF8StringEncoding], [p12Password cStringUsingEncoding:NSUTF8StringEncoding], [txtPath cStringUsingEncoding:NSUTF8StringEncoding]);

    if (ret == 1) {
       
        sm2PrivateKey =  [SM2_SignIdtoken readPrivateKeyFromPath:txtPath];
        sm2publicKey =  [SM2_SignIdtoken readPublicKeyFromPath:txtPath];

    }else{

        return @"";
    }
    NSString  *px = [sm2publicKey substringToIndex:64];

    NSString  *py = [sm2publicKey substringFromIndex:64];
    unsigned char result[72] = {0};
    unsigned long outlen = 64;
    unsigned char dgstssss[32] = {0};
    unsigned long outlenssss = 32;
    if (!JZYT_sm2_sign(sm2p256real,
                       [sm2PrivateKey cStringUsingEncoding:NSUTF8StringEncoding],
                       [px cStringUsingEncoding:NSUTF8StringEncoding],
                       [py cStringUsingEncoding:NSUTF8StringEncoding],
                       [uid cStringUsingEncoding:NSUTF8StringEncoding],
                       "",
                       [str cStringUsingEncoding:NSUTF8StringEncoding],
                       "",
                       [[SM2_SignIdtoken ret32bitString] cStringUsingEncoding:NSUTF8StringEncoding],
                       "",
                       "",(unsigned char *)result,&outlen)) {

        printf("签名失败\n");
        return @"";
    } else {
        printf("签名成功\n");
        NSData *data = [NSData dataWithBytes:result length:outlen];
        NSLog(@"%@",data);
        NSData *dgstdata = [NSData dataWithBytes:dgstssss length:outlenssss];
        NSLog(@"dgstdata = %@",dgstdata);
        NSLog(@"签名数据=== %@",[NSString stringWithFormat:@"%@",[MF_Base64CodecSM2 base64UrlEncodedStringFromBase64String:[dgstdata base64String]]]);
        return [NSString stringWithFormat:@"%@.%@",str,[MF_Base64CodecSM2 base64UrlEncodedStringFromBase64String:[data base64String]]];
    }
}

+(NSString *)readPrivateKeyFromPath:(NSString *)path{ //GBK

    unsigned long encode = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    NSError *error ;
    NSString *content = [NSString stringWithContentsOfFile:path encoding:encode error:&error];
    if (error) {
        NSLog(@"%@",error);
        return @"";

    }else{
        NSArray *Arr = [NSArray array];
        NSArray *Arr1 = [NSArray array];
        Arr = [content componentsSeparatedByString:@"priv:"];
        NSString *str1 = Arr[1];

        Arr1 = [str1 componentsSeparatedByString:@"pub:"];

        NSString *privatekey = Arr1[0];

        NSString *privatekey1 = [privatekey stringByReplacingOccurrencesOfString:@" " withString:@""];

        NSString *privatekey2 =  [privatekey1 stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        NSString *privatekey3 =  [privatekey2 stringByReplacingOccurrencesOfString:@":" withString:@""];

        NSLog(@"私钥 ==== %@",privatekey3);
        return privatekey3;

    }

}
+ (NSString *)readPublicKeyFromPath:(NSString *)path{ //GBK

    unsigned long encode = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    NSError *error ;
    NSString *content = [NSString stringWithContentsOfFile:path encoding:encode error:&error];
    if (error) {
        NSLog(@"%@",error);
        return @"";

    }else{
        NSArray *Arr = [NSArray array];
        NSArray *Arr1 = [NSArray array];
        Arr = [content componentsSeparatedByString:@"pub:"];
        NSString *str1 = Arr[1];

        Arr1 = [str1 componentsSeparatedByString:@"ASN1 OID"];

        NSString *publickey = Arr1[0];

        NSString *publickey1 = [publickey stringByReplacingOccurrencesOfString:@" " withString:@""];

        NSString *publickey2 =  [publickey1 stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        NSString *publickey3 =  [publickey2 stringByReplacingOccurrencesOfString:@":" withString:@""];

        NSLog(@"公钥 ==== %@",publickey3);
        return [publickey3 substringFromIndex:2];

    }

}
+ (NSString*)dictionaryToJson:(NSDictionary *)dic {
    NSError *parseError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dic options:NSJSONWritingPrettyPrinted error:&parseError];
    NSString *string =  [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *string1 = [string stringByReplacingOccurrencesOfString:@" " withString:@""];

    NSString *string2 =  [string1 stringByReplacingOccurrencesOfString:@"\n" withString:@""];

    return string2;
}
+(NSString *)ret32bitString

{

    NSString *randString = @"";
    for(int i=0;i<16;i++)
    {
        int num = arc4random()%0xFFFF;
        NSString *str = [NSString stringWithFormat:@"%02x", num];
        randString = [NSString stringWithFormat:@"%@%@",randString,str] ;
    }

    return randString;

}
+(BOOL )isSM2P12:(NSString *)p12Path password:(NSString *)p12Password{
    NSFileManager *fileManager = [[NSFileManager alloc]init];
    NSString *pathDocuments = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)objectAtIndex:0];
    NSString *createPath = [NSString stringWithFormat:@"%@/Documents/JZYT/",pathDocuments];
    if (![[NSFileManager defaultManager]fileExistsAtPath:createPath]) {

        [fileManager createDirectoryAtPath:createPath withIntermediateDirectories:YES attributes:nil error:nil];

    }else{
    }
    NSString *txtPath = [createPath stringByAppendingString:@"sm2.txt"];
    int ret = getprivateKeyTxt([p12Path cStringUsingEncoding:NSUTF8StringEncoding], [p12Password cStringUsingEncoding:NSUTF8StringEncoding], [txtPath cStringUsingEncoding:NSUTF8StringEncoding]);

    if (ret == 1) {

    unsigned long encode = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    NSError *error ;
    NSString *content = [NSString stringWithContentsOfFile:txtPath encoding:encode error:&error];
    if (error) {
        NSLog(@"%@",error);
        return NO;

    }else{

        if ([content rangeOfString:@"sm2p256v1"].location !=NSNotFound) {

            return YES;
        }
        return NO;

    }
        return NO;
    }else{

        return NO;
    }


}
@end
