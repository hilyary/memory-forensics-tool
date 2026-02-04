@echo off
REM 析镜 LensAnalysis - Windows Nuitka 打包脚本

echo ============================================================
echo   析镜 LensAnalysis - Nuitka 打包工具 (Windows)
echo ============================================================
echo.

REM 检查 Nuitka
python -m nuitka --version >nul 2>&1
if errorlevel 1 (
    echo [×] Nuitka 未安装
    echo [i] 请运行: pip install nuitka
    pause
    exit /b 1
)

echo [√] Nuitka 已安装
echo.

REM 清理旧文件
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build
echo [√] 已清理旧文件
echo.

REM Nuitka 打包命令
echo [i] 开始打包 (需要 5-15 分钟)...
echo.

python -m nuitka ^
    --standalone ^
    --assume-yes-for-downloads ^
    --output-dir=build/nuitka ^
    --output-filename=LensAnalysis.exe ^
    --jobs=4 ^
    --include-data-dir=frontend=frontend ^
    --include-data-dir=backend\plugins=backend/plugins ^
    --include-module=webview ^
    --include-module=webview.platforms.edgechromium ^
    --include-module=docx ^
    --include-module=pefile ^
    --include-module=rich ^
    --include-module=yaml ^
    --include-module=lzma ^
    --nofollow-import-to=matplotlib ^
    --nofollow-import-to=numpy ^
    --nofollow-import-to=pandas ^
    --nofollow-import-to=scipy ^
    --nofollow-import-to=tkinter ^
    --nofollow-import-to=PySide2 ^
    --nofollow-import-to=PySide6 ^
    --nofollow-import-to=PyQt6 ^
    --nofollow-import-to=IPython ^
    --nofollow-import-to=test ^
    --nofollow-import-to=unittest ^
    --windows-disable-console ^
    main.py

if errorlevel 1 (
    echo.
    echo [×] 打包失败
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   打包完成!
echo ============================================================

REM 移动到 dist 目录
if not exist dist mkdir dist
move build\nuitka\LensAnalysis.dist\LensAnalysis.exe dist\ >nul 2>&1

REM 计算大小
for %%A in (dist\LensAnalysis.exe) do set SIZE=%%~zA
set /a SIZEMB=%SIZE%/1048576

echo [√] 可执行文件: dist\LensAnalysis.exe
echo [√] 大小: 约 %SIZEMB% MB
echo.
echo 使用方法:
echo   1. 安装 Volatility 3: pip install volatility3
echo   2. 运行: dist\LensAnalysis.exe
echo.
echo Nuitka 优势:
echo   √ 编译成机器码，性能更好
echo   √ 防反编译能力强（机器码极难还原）
echo   √ 启动速度快
echo.

pause
