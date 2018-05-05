//
//  main.m
//  hexbytescanner
//
//  Created by karek314 on 11/01/2018.
//  Copyright © 2018 karek314. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <objc/message.h>
#include <string>


//uncomment for Xcode
#define NSLog(args...) CustomNSLog(__FILE__,__LINE__,__PRETTY_FUNCTION__,args)

using namespace std;

@interface HexByteScanner : NSObject {}
+(void)main:(const char **)argv;
@end
@implementation HexByteScanner : NSObject


+(void)main:(const char **)argv{
    if (argv[1]) {
        if (!strcmp(argv[1],"scan")) {
            NSLog(@"Scan mode");
            if (argv[2]) {
                if (argv[3]) {
                    NSString *pattern = [[NSString alloc] initWithUTF8String:argv[3]];
                    long check = ([pattern length] % 2);
                    if (check != 0) {
                        NSLog(@"Pattern incorrect: %lu/%lu (incorrect byte)",(unsigned long)[pattern length],[pattern length]+check);
                        exit(2);
                    }
                    NSString *fileName = [[NSString alloc] initWithUTF8String:argv[2]];
                    NSLog(@"File:%@",fileName);
                    NSData *fileData = [NSData dataWithContentsOfFile:fileName];
                    NSTimeInterval start = [[NSDate date] timeIntervalSince1970];
                    NSMutableArray *addressArray = [self ScanData:fileData WithPattern:pattern];
                    NSTimeInterval end = [[NSDate date] timeIntervalSince1970];
                    NSLog(@"\nProgress: 100.00%");
                    NSLog(@"Found locations:%@",addressArray);
                    NSLog(@"Scanning took:%.2fs",end-start);
                } else {
                    NSLog(@"Pattern is missing");
                    CorrectScanUsage();
                }
            } else {
                NSLog(@"Binary name is missing");
                CorrectScanUsage();
            }
        } else if (!strcmp(argv[1],"patch")) {
            NSLog(@"Patch mode");
            if (argv[2]) {
                if (argv[3]) {
                    if (argv[4]) {
                        NSString *fileName = [[NSString alloc] initWithUTF8String:argv[2]];
                        NSLog(@"File:%@",fileName);
                        uint64_t PatchAddress = strtoull(argv[3], NULL, 0);
                        NSLog(@"Patch address: 0x%llx",PatchAddress);
                        NSString *PatchBytes = [[NSString alloc] initWithUTF8String:argv[4]];
                        long check = ([PatchBytes length] % 2);
                        if (check != 0) {
                            NSLog(@"Patch bytes incorrect: %lu/%lu",(unsigned long)[PatchBytes length],[PatchBytes length]+check);
                            exit(2);
                        }
                        uint64_t PatchDistance = 0x1;
                        if (argv[5]) {
                            PatchDistance = strtoull(argv[5], NULL, 0);
                            NSLog(@"Patch distance: 0x%llx",PatchDistance);
                        } else {
                            NSLog(@"Default patch distance: 0x%llx",PatchDistance);
                        }
                        NSData *fileData = [NSData dataWithContentsOfFile:fileName];
                        fileData = [self Patch:fileData WithBytes:PatchBytes AtAddress:PatchAddress WithDistance:PatchDistance];
                        NSString *newFileName = [NSString stringWithFormat:@"%@_patched",fileName];
                        [fileData writeToFile:newFileName options:NSDataWritingAtomic error:nil];
                        NSString *cmd = [NSString stringWithFormat:@"chmod +x %@",newFileName];
                        system([cmd cStringUsingEncoding:NSASCIIStringEncoding]);
                        NSLog(@"Done. Binary %@ saved.",newFileName);
                    } else {
                        NSLog(@"Bytes to patch are missing");
                        CorrectPatchUsage();
                    }
                } else {
                    NSLog(@"Patch address is missing");
                    CorrectPatchUsage();
                }
            } else {
                NSLog(@"Binary name is missing");
                CorrectPatchUsage();
            }
        } else if(strstr(argv[1],".json") != NULL){
            NSLog(@"Json mode");
            if (argv[2]) {
                NSData *json = [NSData dataWithContentsOfFile:[[NSString alloc] initWithUTF8String:argv[1]]];
                NSString *fileName = [[NSString alloc] initWithUTF8String:argv[2]];
                NSLog(@"File:%@",fileName);
                NSLog(@"Config:%@",[[NSString alloc] initWithUTF8String:argv[1]]);
                NSData *fileData = [NSData dataWithContentsOfFile:fileName];
                NSDictionary *jsondict = [NSJSONSerialization JSONObjectWithData:json options:kNilOptions error:nil];
                NSLog(@"Task count: %i",[jsondict count]);
                for (NSDictionary *object in jsondict) {
                    NSString *patchBytes = object[@"patchBytes"];
                    NSString *pattern = [object[@"pattern"] stringByReplacingOccurrencesOfString:@" " withString:@""];
                    uint64_t patchDistance = 0x1;
                    long check = ([patchBytes length] % 2);
                    if (check != 0) {
                        NSLog(@"Patch bytes incorrect: %lu/%lu",(unsigned long)[patchBytes length],[patchBytes length]+check);
                        exit(2);
                    }
                    check = ([pattern length] % 2);
                    if (check != 0) {
                        NSLog(@"Pattern incorrect: %lu/%lu (incorrect byte)",(unsigned long)[pattern length],[pattern length]+check);
                        exit(2);
                    }
                    if (object[@"patchDistance"]) {
                        NSScanner* scanner = [NSScanner scannerWithString:object[@"patchDistance"]];
                        [scanner scanHexLongLong:&patchDistance];
                    }
                    if ([patchBytes isEqualToString:@""]) {
                        NSLog(@"Search Task with pattern %@",pattern);
                    } else {
                        NSLog(@"Patch Task pattern %@ with patch bytes %@ at distance 0x%llx",pattern,patchBytes,patchDistance);
                    }
                    NSTimeInterval start = [[NSDate date] timeIntervalSince1970];
                    NSMutableArray *addressArray = [self ScanData:fileData WithPattern:pattern];
                    NSTimeInterval end = [[NSDate date] timeIntervalSince1970];
                    NSLog(@"\nProgress: 100.00%");
                    NSLog(@"Found locations:%@",addressArray);
                    NSLog(@"Scanning took:%.2fs",end-start);
                    uint64_t address = 0x0;
                    if (![patchBytes isEqualToString:@""]) {
                        if ([addressArray count]==0) {
                            NSLog(@"Can't patch because patch address has not been found");
                        } else if ([addressArray count]==1) {
                            address = strtoull([[NSString stringWithFormat:@"%@",[addressArray objectAtIndex:0]] cStringUsingEncoding:NSASCIIStringEncoding], NULL, 0);
                        } else {
                            address = strtoull([[NSString stringWithFormat:@"%@",[addressArray objectAtIndex:0]] cStringUsingEncoding:NSASCIIStringEncoding], NULL, 0);
                            NSLog(@"There are multiple locations for this pattern, proceeding with first (0x%llx)",address);
                        }
                        if (address != 0x0) {
                            NSLog(@"Patching:0x%llx",address);
                            fileData = [self Patch:fileData WithBytes:patchBytes AtAddress:address WithDistance:patchDistance];
                            NSString *newFileName = [NSString stringWithFormat:@"%@_patched",fileName];
                            [fileData writeToFile:newFileName options:NSDataWritingAtomic error:nil];
                            NSString *cmd = [NSString stringWithFormat:@"chmod +x %@",newFileName];
                            system([cmd cStringUsingEncoding:NSASCIIStringEncoding]);
                            NSLog(@"Done. Binary %@ saved.",newFileName);
                        }
                    }
                }
            } else {
                NSLog(@"Binary name is missing");
                NSLog(@"Example of correct usage ./hexbytescanner test.json MyApp");
            }
        }
    } else {
        NSLog(@"Specify command 'scan', 'patch' or json file");
    }
}


+(NSData*)Patch:(NSData*)inputData WithBytes:(NSString*)StringBytes AtAddress:(uint64_t)PatchAddress WithDistance:(uint64_t)PatchDistance{
    NSMutableData *data = [NSMutableData dataWithData:inputData];
    PatchAddress += PatchDistance;
    uint64_t lenght = [inputData length];
    StringBytes = [StringBytes stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSLog(@"Patching with bytes: %@",StringBytes);
    NSLog(@"Data Lenght %llu",lenght);
    NSData *tmp = [inputData subdataWithRange:NSMakeRange(PatchAddress, [StringBytes length]/2)];
    NSLog(@"[0x%llx]Current opcode: %@",PatchAddress,[self RemoveWhitespaces:[self Trim:[NSString stringWithFormat:@"%@",tmp]]]);
    [data replaceBytesInRange:NSMakeRange(PatchAddress, [StringBytes length]/2) withBytes:[[self dataFromString:StringBytes] bytes]];
    inputData = [NSData dataWithData:data];
    tmp = [inputData subdataWithRange:NSMakeRange(PatchAddress, [StringBytes length]/2)];
    NSLog(@"[0x%llx]Replaced opcode: %@",PatchAddress,[self RemoveWhitespaces:[self Trim:[NSString stringWithFormat:@"%@",tmp]]]);
    return inputData;
}


+(NSMutableArray*)ScanData:(NSData*)inputData WithPattern:(NSString*)pattern{
    uint64_t lenght = [inputData length];
    NSMutableArray *addressArray = [NSMutableArray new];
    pattern = [pattern stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSMutableArray *patternArray = [NSMutableArray new];
    __block NSData *data = [NSData dataWithData:inputData];
    __block int patternLenght = 0;
    while (![pattern isEqualToString:@""]) {
        NSString *pbyte = [pattern substringToIndex:2];
        if ([pbyte isEqualToString:@"??"]) {
            [patternArray addObject:pbyte];
        } else {
            [patternArray addObject:[self dataFromString:pbyte]];
        }
        pattern = [pattern substringFromIndex:2];
        patternLenght++;
    }
    NSLog(@"Searching with pattern: %@",[self PatternToString:patternArray]);
    NSLog(@"Data Lenght %llu",lenght);
    NSLog(@"Starting scanner");
    unsigned long numberOfThreads = [[NSProcessInfo processInfo] activeProcessorCount];
    dispatch_group_t group = dispatch_group_create();
    dispatch_queue_t queue = dispatch_queue_create("hexbytescanner.queue",DISPATCH_QUEUE_CONCURRENT);
    __block int log=0;
    __block uint64_t progress = 0;
    __block uint64_t threadDataSize = lenght/numberOfThreads;
    for (int th=1; th<=numberOfThreads; th++) {
        __block NSMutableArray *result = [NSMutableArray new];
        __block NSData *threadData = [NSData new];
        __block uint64_t safe_min = ((th-1)*threadDataSize)-patternLenght;
        if (th==1) {
            threadData = [data subdataWithRange:NSMakeRange(0, threadDataSize)];
        } else {
            threadData = [data subdataWithRange:NSMakeRange(safe_min, threadDataSize)];
        }
        dispatch_group_async(group, queue, ^{
            int patternMatch = 0;
            for (uint64_t i=0; i<[threadData length]; i++) {
                @autoreleasepool {
                    if (th == 1) {
                        log++;
                        if (log > 300000) {
                            printf("\rProgress: %3.2f%%",(Float64(progress)/Float64(lenght))*100);
                            fflush(stdout);
                            log = 0;
                        }
                    }
                    progress++;
                    NSData *byte = [threadData subdataWithRange:NSMakeRange(i, 1)];
                    NSData *pat_byte = [patternArray objectAtIndex:patternMatch];
                    if ([byte isEqualToData:pat_byte]) {
                        patternMatch++;
                        [result addObject:byte];
                        if (patternMatch == patternLenght) {
                            uint64_t address = 0x0;
                            if (th == 1) {
                                address = i;
                            } else {
                                address = i+safe_min;
                            }
                            NSLog(@"\nFound matching pattern at 0x%llx -> %@",address,[self PatternToString:result]);
                            [addressArray addObject:[NSString stringWithFormat:@"0x%llx",address]];
                            patternMatch = 0;
                        }
                    } else if ([[NSString stringWithFormat:@"%@",pat_byte] isEqualToString:@"??"]) {
                        patternMatch++;
                        [result addObject:byte];
                    } else {
                        patternMatch = 0;
                        result = [NSMutableArray new];
                    }
                }
            }
        });
    }
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    return addressArray;
}


+(NSString*)PatternToString:(NSMutableArray*)array{
    return [self Trim:[array componentsJoinedByString:@" "]];
}


+(NSString*)Trim:(NSString*)input{
    return [[input stringByReplacingOccurrencesOfString:@"<" withString:@""]stringByReplacingOccurrencesOfString:@">" withString:@""];
}

+(NSString*)RemoveWhitespaces:(NSString*)input{
    return [input stringByReplacingOccurrencesOfString:@" " withString:@""];
}

+(NSData *)dataFromString:(NSString *)string{
    string = [string lowercaseString];
    NSMutableData *data= [NSMutableData new];
    unsigned char byte;
    char chars[3] = {'\0','\0','\0'};
    int i = 0;
    unsigned long length = string.length;
    while (i < length-1) {
        char c = [string characterAtIndex:i++];
        if (c < '0' || (c > '9' && c < 'a') || c > 'f')
            continue;
        chars[0] = c;
        chars[1] = [string characterAtIndex:i++];
        byte = strtol(chars, NULL, 16);
        [data appendBytes:&byte length:1];
    }
    return data;
}


void CustomNSLog(const char *file, int line, const char *name, NSString *format, ...){
    va_list ap;
    va_start(ap, format);
    if (![format hasSuffix: @"\n"]){format = [format stringByAppendingString: @"\n"];}
    NSString *body = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    fprintf(stderr,"%s",[body UTF8String]);
}


void CorrectScanUsage(){
    NSLog(@"Example of correct usage ./hexbytescanner scan MyApp E103??AA????E0");
}


void CorrectPatchUsage(){
    NSLog(@"Example of correct usage ./hexbytescanner patch MyApp 0x184dfc 1F2003D5 0x1");
}


@end


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"HexByteScanner by karek314");
        objc_msgSend(objc_getClass("HexByteScanner"),sel_registerName("main:"),argv);
    }
    return 0;
}
