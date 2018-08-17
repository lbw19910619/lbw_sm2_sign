//
//  SM2_SignIdtoken.h
//  SM2OC
//
//  Created by 九州云腾 on 2018/4/20.
//  Copyright © 2018年 九州云腾. All rights reserved.
//

#import <UIKit/UIKit.h>
@interface SM2_SignIdtoken : NSObject


+ (NSString *)getSM2_idtokenWithP12Path:(NSString *)p12Path password:(NSString *)p12Password head:(NSDictionary *)header payload:(NSDictionary *)payload;
+(BOOL )isSM2P12:(NSString *)p12Path password:(NSString *)p12Password;
@end
