#import <Cocoa/Cocoa.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // 获取可执行文件所在目录
        NSString *executablePath = [[NSBundle mainBundle] executablePath];
        NSString *executableDir = [executablePath stringByDeletingLastPathComponent];
        NSString *pythonBinary = [executableDir stringByAppendingPathComponent:@"LensAnalysis"];

        // 检查 Python 可执行文件是否存在
        if (![[NSFileManager defaultManager] fileExistsAtPath:pythonBinary]) {
            NSLog(@"Python binary not found at: %@", pythonBinary);
            return 1;
        }

        // 创建 NSTask 来启动 Python 可执行文件
        NSTask *task = [[NSTask alloc] init];
        [task setLaunchPath:pythonBinary];
        [task setCurrentDirectoryPath:executableDir];

        // 继承当前环境
        [task setEnvironment:[[NSProcessInfo processInfo] environment]];

        // 设置标准输入输出为 null（避免写入失败导致崩溃）
        NSFileHandle *nullHandle = [NSFileHandle fileHandleForReadingAtPath:@"/dev/null"];
        [task setStandardInput:nullHandle];
        [task setStandardOutput:nullHandle];
        [task setStandardError:nullHandle];

        // 启动任务
        @try {
            [task launch];
            [task waitUntilExit];
            return [task terminationStatus];
        } @catch (NSException *exception) {
            NSLog(@"Failed to launch Python binary: %@", exception);
            return 1;
        }
    }
    return 0;
}
