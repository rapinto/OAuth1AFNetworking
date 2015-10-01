//
//  OAuth1OperationManager.m
//
//
//  Created by Raphaël Pinto on 25/06/2014.
//
// The MIT License (MIT)
// Copyright (c) 2015 Raphael Pinto.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.



#import "OAuth1OperationManager.h"
#import "AFOAuth1Token.h"
#import "AFHTTPRequestOperation.h"
#import "QueryStringPair.h"
#import <CommonCrypto/CommonCrypto.h>
#import "Utils.h"



static NSString * const kAFOAuth1Version = @"1.0";


static inline NSString * NSStringFromAFOAuthSignatureMethod(AFOAuthSignatureMethod signatureMethod) {
    switch (signatureMethod) {
        case AFPlainTextSignatureMethod:
            return @"PLAINTEXT";
        case AFHMACSHA1SignatureMethod:
            return @"HMAC-SHA1";
        default:
            return nil;
    }
}


static inline NSString * AFNounce() {
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, uuid);
    CFRelease(uuid);
    
    return (NSString *)CFBridgingRelease(string);
}


static inline NSString * AFPlainTextSignature(NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    NSString *signature = [NSString stringWithFormat:@"%@&%@", consumerSecret, secret];
    return signature;
}


static NSString * AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(NSString *string, NSStringEncoding encoding) {
    static NSString * const kAFCharactersToBeEscaped = @":/?&=;+!@#$()',*";
    static NSString * const kAFCharactersToLeaveUnescaped = @".";
    
    return (__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (__bridge CFStringRef)string, (__bridge CFStringRef)kAFCharactersToLeaveUnescaped, (__bridge CFStringRef)kAFCharactersToBeEscaped, CFStringConvertNSStringEncodingToEncoding(encoding));
}



@interface OAuth1OperationManager ()
@property (readwrite, nonatomic, copy) NSString *key;
@property (readwrite, nonatomic, copy) NSString *secret;
@end


@implementation OAuth1OperationManager



#pragma mark -
#pragma mark Singleton Methods



static OAuth1OperationManager* _sharedInstance = nil;
static dispatch_once_t onceToken = 0;




+ (OAuth1OperationManager*)sharedInstance
{
    static OAuth1OperationManager *sharedInstance = nil;
    
    dispatch_once(&onceToken, ^{
        sharedInstance = [[[self class] alloc] init];
    });
    return sharedInstance;
}



#pragma mark -
#pragma mark Object Life Cycle Methods



- (id)initWithBaseURL:(NSURL *)url
                  key:(NSString *)clientID
               secret:(NSString *)secret
{
    self = [self initWithBaseURL:url];
    
    if (self)
    {
        self.key = clientID;
        self.secret = secret;
        self.signatureMethod = AFHMACSHA1SignatureMethod;
        self.stringEncoding = NSUTF8StringEncoding;
    }
    
    return self;
}



#pragma mark -
#pragma mark oAuth Methods



- (NSDictionary *)OAuthParameters
{
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    parameters[@"oauth_version"] = kAFOAuth1Version;
    parameters[@"oauth_signature_method"] = NSStringFromAFOAuthSignatureMethod(self.signatureMethod);
    parameters[@"oauth_consumer_key"] = self.key;
    parameters[@"oauth_timestamp"] = [@(floor([[NSDate date] timeIntervalSince1970])) stringValue];
    parameters[@"oauth_nonce"] = AFNounce();
    
    if (self.realm) {
        parameters[@"realm"] = self.realm;
    }
    
    return parameters;
}


NSArray * QueryStringPairsFromKeyAndValue(NSString *key, id value) {
    NSMutableArray *mutableQueryStringComponents = [NSMutableArray array];
    
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dictionary = value;
        // Sort dictionary keys to ensure consistent ordering in query string, which is important when deserializing potentially ambiguous sequences, such as an array of dictionaries
        NSSortDescriptor *sortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"description" ascending:YES selector:@selector(caseInsensitiveCompare:)];
        [[[dictionary allKeys] sortedArrayUsingDescriptors:[NSArray arrayWithObject:sortDescriptor]] enumerateObjectsUsingBlock:^(id nestedKey, __unused NSUInteger idx, __unused BOOL *stop) {
            id nestedValue = [dictionary objectForKey:nestedKey];
            if (nestedValue) {
                [mutableQueryStringComponents addObjectsFromArray:QueryStringPairsFromKeyAndValue((key ? [NSString stringWithFormat:@"%@[%@]", key, nestedKey] : nestedKey), nestedValue)];
            }
        }];
    } else if ([value isKindOfClass:[NSArray class]]) {
        NSArray *array = value;
        [array enumerateObjectsUsingBlock:^(id nestedValue, __unused NSUInteger idx, __unused BOOL *stop) {
            [mutableQueryStringComponents addObjectsFromArray:QueryStringPairsFromKeyAndValue([NSString stringWithFormat:@"%@[]", key], nestedValue)];
        }];
    } else if ([value isKindOfClass:[NSSet class]]) {
        NSSet *set = value;
        [set enumerateObjectsUsingBlock:^(id obj, BOOL *stop) {
            [mutableQueryStringComponents addObjectsFromArray:QueryStringPairsFromKeyAndValue(key, obj)];
        }];
    } else {
        [mutableQueryStringComponents addObject:[[QueryStringPair alloc] initWithField:key value:value]];
    }
    return mutableQueryStringComponents;
}


NSString * AFHMACSHA1Signature(NSURL *url,NSString *method, NSDictionary* _HeaderParameters, NSString *consumerSecret, NSString *tokenSecret, NSStringEncoding stringEncoding) {
    NSString *secret = tokenSecret ? tokenSecret : @"";
    
    NSString *secretString = [NSString stringWithFormat:@"%@&%@", AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(consumerSecret, stringEncoding), AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(secret, stringEncoding)];
    NSData *secretStringData = [secretString dataUsingEncoding:stringEncoding];
    
    NSString *queryString = AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[[[url query] componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@"&"], stringEncoding);
    NSString *requestString = [NSString stringWithFormat:@"%@&%@", method, AFPercentEscapedQueryStringPairMemberFromStringWithEncoding([[url absoluteString] componentsSeparatedByString:@"?"][0], stringEncoding)];
    
    if ([queryString length] > 0)
    {
        requestString = [requestString stringByAppendingFormat:@"&%@", queryString];
    }
    
    NSArray *sortedComponents = [[AFQueryStringFromParametersWithEncoding(_HeaderParameters, stringEncoding) componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    
    requestString = [requestString stringByAppendingString:@"&"];
    
    int i = 0;
    for (id anObj in sortedComponents)
    {
        if ([anObj isKindOfClass:[NSString class]])
        {
            if (i > 0)
            {
                requestString = [requestString stringByAppendingString:AFPercentEscapedQueryStringPairMemberFromStringWithEncoding(@"&", stringEncoding)];
            }
            
            requestString = [requestString stringByAppendingString:AFPercentEscapedQueryStringPairMemberFromStringWithEncoding((NSString*)anObj, stringEncoding)];
            
            i++;
        }
    }
    
    NSData *requestStringData = [requestString dataUsingEncoding:stringEncoding];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CCHmacContext cx;
    CCHmacInit(&cx, kCCHmacAlgSHA1, [secretStringData bytes], [secretStringData length]);
    CCHmacUpdate(&cx, [requestStringData bytes], [requestStringData length]);
    CCHmacFinal(&cx, digest);
    
    return [Utils AFEncodeBase64WithData:[NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH]];
}


NSArray * QueryStringPairsFromDictionary(NSDictionary *dictionary) {
    return QueryStringPairsFromKeyAndValue(nil, dictionary);
}


NSString * AFQueryStringFromParametersWithEncoding(NSDictionary *parameters, NSStringEncoding stringEncoding) {
    NSMutableArray *mutablePairs = [NSMutableArray array];
    for (QueryStringPair *pair in QueryStringPairsFromDictionary(parameters)) {
        if (![pair.field isEqualToString:@"realm"])
        {
            [mutablePairs addObject:[pair URLEncodedStringValueWithEncoding:stringEncoding]];
        }
        else
        {
            [mutablePairs addObject:[NSString stringWithFormat:@"%@=%@", pair.field, pair.value]];
        }
    }
    
    return [mutablePairs componentsJoinedByString:@"&"];
}


- (NSString *)authorizationHeaderForMethod:(NSString *)method
                                      path:(NSString *)path
                                parameters:(NSDictionary *)parameters
{
    static NSString * const kAFOAuth1AuthorizationFormatString = @"OAuth %@";
    
    NSMutableDictionary *mutableParameters = parameters ? [parameters mutableCopy] : [NSMutableDictionary dictionary];
    NSMutableDictionary *mutableAuthorizationParameters = [NSMutableDictionary dictionary];
    
    if (self.key && self.secret) {
        [mutableAuthorizationParameters addEntriesFromDictionary:[self OAuthParameters]];
        if (self.accessToken) {
            mutableAuthorizationParameters[@"oauth_token"] = self.accessToken.key;
        }
    }
    
    [mutableParameters enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if ([key isKindOfClass:[NSString class]] && [key hasPrefix:@"oauth_"]) {
            mutableAuthorizationParameters[key] = obj;
        }
    }];
    
    [mutableParameters addEntriesFromDictionary:mutableAuthorizationParameters];
    mutableAuthorizationParameters[@"oauth_signature"] = [self OAuthSignatureForMethod:method path:path parameters:mutableParameters token:self.accessToken];
    
    NSArray *sortedComponents = [[AFQueryStringFromParametersWithEncoding(mutableAuthorizationParameters, self.stringEncoding) componentsSeparatedByString:@"&"] sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    
    NSMutableArray *mutableComponents = [NSMutableArray array];
    for (NSString *component in sortedComponents) {
        NSArray *subcomponents = [component componentsSeparatedByString:@"="];
        if ([subcomponents count] == 2) {
            [mutableComponents addObject:[NSString stringWithFormat:@"%@=\"%@\"", subcomponents[0], subcomponents[1]]];
        }
    }
    
    return [NSString stringWithFormat:kAFOAuth1AuthorizationFormatString, [mutableComponents componentsJoinedByString:@","]];
}


- (NSString *)OAuthSignatureForMethod:(NSString *)method
                                 path:(NSString *)path
                           parameters:(NSDictionary *)_Parameters
                                token:(AFOAuth1Token *)token
{
    NSURL* lURL = [NSURL URLWithString:path];
    
    NSString *tokenSecret = token ? token.secret : nil;
    
    switch (self.signatureMethod)
    {
        case AFPlainTextSignatureMethod:
            return AFPlainTextSignature(self.secret, tokenSecret, self.stringEncoding);
        case AFHMACSHA1SignatureMethod:
            return AFHMACSHA1Signature(lURL, method, _Parameters, self.secret, tokenSecret, self.stringEncoding);
        default:
            return nil;
    }
}


@end
