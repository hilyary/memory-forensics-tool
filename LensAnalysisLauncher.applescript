tell application "System Events"
    try
        do shell script "open /Applications/LensAnalysis.app"
    on error errMsg
        display dialog "启动失败: " & errMsg buttons {"确定"} default button 1 with icon stop
    end try
end tell
