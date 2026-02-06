#import <Cocoa/Cocoa.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // 获取可执行文件所在目录
        NSString *executablePath = [[NSBundle mainBundle] executablePath];
        NSString *executableDir = [executablePath stringByDeletingLastPathComponent];
        NSString *pythonBinary = [executableDir stringByAppendingPathComponent:@"LensAnalysis.bin"];

        NSLog(@"Launcher: Starting, dir=%@", executableDir);

        // 检查 Python 可执行文件是否存在
        if (![[NSFileManager defaultManager] fileExistsAtPath:pythonBinary]) {
            NSLog(@"ERROR: Python binary not found at: %@", pythonBinary);
            return 1;
        }

        // 创建 NSTask 来启动 Python 可执行文件
        NSTask *task = [[NSTask alloc] init];
        [task setLaunchPath:pythonBinary];
        [task setCurrentDirectoryPath:executableDir];
        [task setEnvironment:[[NSProcessInfo processInfo] environment]];

        // 启动任务
        @try {
            [task launch];
            [task waitUntilExit];
            return [task terminationStatus];
        } @catch (NSException *exception) {
            NSLog(@"ERROR: Failed to launch: %@", exception);
            return 1;
        }
    }
    return 0;
}
