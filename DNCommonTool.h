/*
 //
 //  DNHTTPProxyManager.h
 //  HTTPAgent
 //
 //  Created by 王缘 on 16/11/16.
 //  Copyright © 2016年 . All rights reserved.
 //  Company .
 
 */
#import <Foundation/Foundation.h>
#import "DNResultHanderDef.h"

@class DNAuthParam;
@interface DNCommonTool : NSObject
//对象转字典
+ (NSDictionary*)getObjectData:(id)obj;

//MD5加密
+ (NSString *)md5:(NSString *)input;

//SHA512加密
+ (NSString *)sha512:(NSString *)input;

/**
 ** 动态key生成算法
 ** 将请求参数按照 JSON 格式进行 Base64 转码
 **/
+ (NSString *)createKeyWithParamDict:(NSDictionary *)dict;

/**
 ** sign签名生成算法
 将所有请求参数按照参数名升序排序, 排序后，按请求参数名及参数值相互连接组成字符串，并在前面加入DNION成为新的字符串s
 token签名sign: Sign=MD5(SHA512(s)+secretKey)
 其他签名sign:   Sign=MD5(SHA512(s)+token)
 
 **/
+ (NSString *)createSignWithParamDict:(NSDictionary *)dict SecretKey:(NSString *)key;


//返回运营商信息
+ (DNCarrierName)getCarrierName;

//检查是否是正常的是手机号码
+ (BOOL)isMobileNumber:(NSString *)mobileNum;

// 是否WIFI
+ (BOOL)isEnableWIFI;
// 是否3G
+ (BOOL)isEnable3G;

//生成16位随机向量
+ (NSString *)randstringWithLength:(NSUInteger)length;

//获取当前时间戳 单位ms
+ (NSString *)currentTimeStampString;

//AES-256-CBC加密
+ (NSData *)AES256EncryptWithData:(NSData *)data Key:(NSString *)key iv:(NSString *)iv;
//AES-256-CBC解密
+ (NSData *)AES256DecryptWithData: (NSData *)data Key:(NSString *)key iv:(NSString *)iv;
//3DES 加密
+ (NSString *)TripleDESEncryptWithplainText:(NSString*)plainText key:(NSString *)key iv:(NSString *)iv;

@end
