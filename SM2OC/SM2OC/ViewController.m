//
//  ViewController.m
//  SM2Simple
//
//  Created by bolei on 16/12/1.
//  Copyright © 2016年 pingan. All rights reserved.
//

#import "ViewController.h"
#import <openssl/sm2.h>
#import "sm2P12.h"
#import "MF_Base64AdditionsSM2.h"
#import "sm2ToOC.h"
#import "NSData+HexString.h"
#import "SM2_SignIdtoken.h"

@interface ViewController ()
{

    unsigned int _outlen;
    unsigned char _result[256];
}
@property(strong,nonatomic)NSString *px;
@property(strong,nonatomic)NSString *py;
@property(strong,nonatomic)NSString *priviteKey;
@property (weak, nonatomic) IBOutlet UITextView *privateKeyTextView;
@property (weak, nonatomic) IBOutlet UITextView *publicKeyTextView;
@property (weak, nonatomic) IBOutlet UITextView *signDataTextView;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.

//    NSString *path = [[NSBundle mainBundle] pathForResource:@"Jzyt" ofType:@"p12"];

//    NSDictionary *head = @{@"alg":@"SM2",@"kid":@"c02305a5-7bbe-4bc4-ba17-91fc58a6f6f5"};
//    NSDictionary *payload = @{@"iat":@1524554649,@"deviceId":@"8A27F954-1227-4CE6-B0EF-9CA33E8A0323",@"@jti":@"WJLXQPHMHOSMTHRVGZGMCF",@"pushId":@"ff4d97725cf5321f1d5ffea1d41cb52fbc150646b32c0dadb579fcf088bd6c39",@"sub":@"IDS_Subject",@"nbf":@1524554589,@"exp":@1524555249,@"aud":@"IDS_AUDIENCE",@"timestamp":@1524554649000,@"simId":@"8A27F954-1227-4CE6-B0EF-9CA33E8A0323"};
//
//    NSString *signedString =    [SM2_SignIdtoken getSM2_idtokenWithP12Path:path password:@"XtXz2DVsxEWGcQT8" head:head payload:payload];
//    NSLog(@"signedString = %@",signedString);

}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.


}
- (IBAction)sm2_sign:(id)sender {
    if (self.privateKeyTextView.text.length == 0 || self.publicKeyTextView.text.length == 0 || self.publicKeyTextView.text.length != 128) {

        UIAlertController *alertController= [UIAlertController alertControllerWithTitle:@"提示!" message:@"请输入正确的公私钥" preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil];
        [alertController addAction:cancelAction];
        [self presentViewController:alertController animated:YES completion:nil];
        return;
    }
    NSString *str = @"你是帅哥";

    NSString *uid = @"1234567812345678";
    EC_GROUP *sm2p256real = new_ec_group(1,
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
                                         "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
                                         "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                                         "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                                         "1");



    NSString  *px = [self.publicKeyTextView.text substringToIndex:64];

    NSString  *py = [self.publicKeyTextView.text substringFromIndex:64];
    unsigned char result[256] = {0};
    unsigned long outlen = 256;
    if (!JZYT_sm2_sign(sm2p256real,
                       [self.privateKeyTextView.text cStringUsingEncoding:NSUTF8StringEncoding],
                       [px cStringUsingEncoding:NSUTF8StringEncoding],
                       [py cStringUsingEncoding:NSUTF8StringEncoding],
                       [uid cStringUsingEncoding:NSUTF8StringEncoding],
                       "",
                       [str cStringUsingEncoding:NSUTF8StringEncoding],
                       "",
                       "6CB28D99385C175C94F94E934817663FC127",
                       "",
                       "",result,&outlen)) {
        UIAlertController *alertController= [UIAlertController alertControllerWithTitle:@"提示!" message:@"签名失败" preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil];
        [alertController addAction:cancelAction];
        [self presentViewController:alertController animated:YES completion:nil];
        printf("sm2 sign p256 failed\n");
    } else {
        printf("sm2 sign p256 passed\n");

        for (int i = 0; i<256; i++)
        {
            _result[i] = result[i];
        }

        NSData *data = [NSData dataWithBytes:(unsigned char *)result length:outlen];
        _outlen = [data length];
        self.signDataTextView.text =  [data hexStringFromData:data];
        NSLog(@"%@",data);

    }

}
- (IBAction)sm2_vertify:(id)sender {

    NSString *str = @"你是帅哥";

    NSString *uid = @"1234567812345678";
    EC_GROUP *sm2p256real = new_ec_group(1,
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
                                         "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
                                         "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                                         "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
                                         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                                         "1");



    NSString  *px = [self.publicKeyTextView.text substringToIndex:64];

    NSString  *py = [self.publicKeyTextView.text substringFromIndex:64];

    if (!JZYT_sm2_verify(sm2p256real,
                         "",
                         [px cStringUsingEncoding:NSUTF8StringEncoding],
                         [py cStringUsingEncoding:NSUTF8StringEncoding],
                         [uid cStringUsingEncoding:NSUTF8StringEncoding], [str cStringUsingEncoding:NSUTF8StringEncoding], _result,_outlen)){
        UIAlertController *alertController= [UIAlertController alertControllerWithTitle:@"提示!" message:@"验签失败" preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil];
        [alertController addAction:cancelAction];
        [self presentViewController:alertController animated:YES completion:nil];
        printf("sm2 verify p256 failed\n");
    } else {
        printf("sm2 verify p256 passed\n");
        UIAlertController *alertController= [UIAlertController alertControllerWithTitle:@"提示!" message:@"验签成功" preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleCancel handler:nil];
        [alertController addAction:cancelAction];
        [self presentViewController:alertController animated:YES completion:nil];
    }

}



-(NSString *)readPrivateKeyFromPath:(NSString *)path{ //GBK

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
- (NSString *)readPublicKeyFromPath:(NSString *)path{ //GBK

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
-(NSString*)dictionaryToJson:(NSDictionary *)dic {
    NSError *parseError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dic options:NSJSONWritingPrettyPrinted error:&parseError];
    NSString *string =  [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *string1 = [string stringByReplacingOccurrencesOfString:@" " withString:@""];

    NSString *string2 =  [string1 stringByReplacingOccurrencesOfString:@"\n" withString:@""];

    return string2;
}
-(NSString *)ret32bitString

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

@end
