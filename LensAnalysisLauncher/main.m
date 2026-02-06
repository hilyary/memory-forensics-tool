#import <Cocoa/Cocoa.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // 使用 NSWorkspace 启动 LensAnalysis.app
        // 这和用户在终端运行 `open /Applications/LensAnalysis.app` 效果相同
        NSURL *appURL = [NSURL fileURLWithPath:@"/Applications/LensAnalysis.app"];

        [[NSWorkspace sharedWorkspace] openURL:appURL];

        return 0;
    }
    return 0;
}
