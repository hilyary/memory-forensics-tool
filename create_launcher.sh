#!/bin/bash
# 创建一个启动器 .app，使用 open 命令启动主应用

LAUNCHER_APP="dist/LensAnalysis.app"

# 创建启动器应用结构
mkdir -p "$LAUNCHER_APP/Contents/MacOS"
mkdir -p "$LAUNCHER_APP/Contents/Resources"

# 创建 Info.plist
cat > "$LAUNCHER_APP/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>LensAnalysisLauncher</string>
    <key>CFBundleIdentifier</key>
    <string>com.lensanalysis.launcher</string>
    <key>CFBundleName</key>
    <string>LensAnalysis</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSBackgroundOnly</key>
    <false/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# 创建启动器可执行文件（实际上是一个指向原始 Nuitka app 的符号链接）
# 但由于我们已经在 dist/LensAnalysis.app 中，我们需要重新组织结构
# 让我们先重命名 Nuitka 生成的 app

echo "启动器 app 结构已创建"
