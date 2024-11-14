REM Main script for timeoutvpn
(
    echo rm main.py
    echo rm timeoutvpn.sh
    echo wget https://raw.githubusercontent.com/timeoutsoft/setvpn/refs/heads/master/main.py
    echo wget https://raw.githubusercontent.com/timeoutsoft/setvpn/refs/heads/master/timeoutvpn.sh
    echo chmod +x timeoutvpn.sh
    echo ./timeoutvpn.sh

) | ssh -o "StrictHostKeyChecking=no" root@xxx.xxx.xxx.xxx


pause
pause
pause
