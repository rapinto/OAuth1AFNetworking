//
//  RPHTTPOperationManager.m
//
//
//  Created by Raphaël Pinto on 06/08/2015.
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



#import "RPHTTPOperationManager.h"



@implementation RPHTTPOperationManager



#pragma mark -
#pragma mark Singleton Methods



static RPHTTPOperationManager* _sharedInstance = nil;
static dispatch_once_t onceToken = 0;




+ (RPHTTPOperationManager*)sharedInstance
{
    static RPHTTPOperationManager *sharedInstance = nil;
    
    dispatch_once(&onceToken, ^{
        sharedInstance = [[[self class] alloc] init];
    });
    return sharedInstance;
}


+(void)setSharedInstance:(RPHTTPOperationManager*)instance
{
    _sharedInstance = instance;
}


+ (RPHTTPOperationManager*)getSharedInstance
{
    return _sharedInstance;
}



#pragma mark -
#pragma mark Data Management Methods



+ (void)cancelRequestWithMethod:(NSString*)_Method url:(NSString*)_URL
{
    for (NSOperation *anOperation in [RPHTTPOperationManager sharedInstance].operationQueue.operations)
    {
        if([anOperation isKindOfClass:[AFHTTPRequestOperation class]])
        {
            AFHTTPRequestOperation* requestOperation = (AFHTTPRequestOperation*)anOperation;
            
            if ([requestOperation.request.HTTPMethod isEqualToString:_Method] &&
                [[requestOperation.request.URL absoluteString] isEqualToString:_URL])
            {
                [anOperation cancel];
            }
        }
    }
}



@end
