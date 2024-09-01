#!/bin/sh
# Made by Sangwon Yun, 2020.
# Root 권한 체크

if [ "$EUID" -ne 0 ]
	then 
		echo "root 권한으로 스크립트를 실행하여 주십시오."
	exit
fi

OUT=`hostname`"_Digno".txt

echo "    _   __   __  ____            _       _   "
echo "   / \  \ \ / / / ___|  ___ _ __(_)_ __ | |_ "
echo "  / _ \  \ V /  \___ \ / __| '__| | '_ \| __| "
echo " / ___ \ _| |_   ___) | (__| |  | | |_) | |_  "
echo "/_/   \_(_)_(_) |____/ \___|_|  |_| .__/ \__| "
echo "                                |_|           "
echo "Warning! This Script Dignogistics for RHEL 7 Server to check the Security Risk made by KISA."
echo "If you are running this script to other Operating System(Such as, RHEL8, Ubuntu, Unix) change the script for your operating system."
echo "For more information, Check the KISA Manual."
echo "" >> $OUT 2>&1

echo "*********************************************RHEL7/Centos7 Dignogistics Script*********************************************" >> $OUT 2>&1
echo "*******************************************************Made By Andrew******************************************************" >> $OUT 2>&1
	echo "" >> $OUT 2>&1
	echo "이 진단 스크립트를 RHEL/Centos 7 에서 작동하지 않을 경우, 부정확한 값이 나올수 있습니다." >> $OUT 2>&1
	echo "만약 위에 사례에 해당하는 경우, 출력값을 참고용으로만 사용하시기 바랍니다." >> $OUT 2>&1
	echo "만약 결과값이 나오지 않는다면, 수정한 스크립트에 오류가 있거나 값이 파일안에 존재하지 않음으로 판단하십시요." >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "*******************************************************System Information**************************************************" >> $OUT 2>&1
	if test -f /etc/centos-release
		then
			echo "Centos Version:" `head -n 1 /etc/centos-release` >> $OUT 2>&1
		elif test -f /etc/redhat-release
			then 	
				echo "RHEL Version:" `head -n 1 /etc/redhat-release` >> $OUT 2>&1
			else
				echo "이 운영체제는 RHEL/Centos가 아닙니다." >> $OUT 2>&1
				echo "OS Information:" `head -n 1 /etc/os-release`>> $OUT 2>&1
	fi	 
	echo "Hostname :" `uname -n` >> $OUT 2>&1
	echo "Kernel Version :" `uname -r` >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "*******************************************************Network Information**************************************************" >> $OUT 2>&1
	ip a >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "**************************************************************Time**********************************************************" >> $OUT 2>&1
	date >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "*****************************************************Start Check Security Risk**********************************************" 

echo "*****************************************************Start Check Security Risk**********************************************" >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "*************************************************************계정 관리********************************************************" 

echo "*************************************************************계정 관리********************************************************" >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-1. ROOT 계정 원격 접속 제한" 
echo "1-1. ROOT 계정 원격 접속 제한" >> $OUT 2>&1
	echo "판단기준: 원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속이 차단되어 있는지 확인" >> $OUT 2>&1
	echo "/etc/pam.d/login 파일을 아래에 출력합니다." >> $OUT 2>&1
	echo "판단 기준: pam.securetty.so 파일 로드 여부" >> $OUT 2>&1
	echo "************************************************************Login File******************************************************" >> $OUT 2>&1 
	cat /etc/pam.d/login >> $OUT 2>&1
echo "" >> $OUT 2>&1
#/etc/ssh/sshd_Config 파일에 PermitRootLogin 항목 확인(주통망기반시설 취약점 가이드에는 포함 되어 있지 않음)
#필요하지 않을 경우 53-55번 라인 주석 처리
echo "sshd_config 항목은 선택 진단 항목입니다." >> $OUT 2>&1
	echo "sshd_config 파일의 PermitRootLogin 항목 확인 (주통망기반시설 취약점 가이드에는 포함 되어 있지 않음)" >> $OUT 2>&1
	cat /etc/ssh/sshd_config | grep PermitRootLogin >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-2. 패스워드 복잡성 설정" 
echo "1-2. 패스워드 복잡성 설정" >> $OUT 2>&1
	echo "판단기준: 영문, 숫자, 특수문자 3가지 모두 조합하여 8자리 미만의 길이가 패스워드로 설정된 경우 (공공기관은 9자리 미만)" >> $OUT 2>&1
	echo "/etc/pam.d/system-auth 파일을 확인합니다." >> $OUT 2>&1
	echo "아래에 system-auth 파일을 출력합니다." >> $OUT 2>&1
	echo "************************************************************System-Auth****************************************************" >> $OUT 2>&1 
	cat /etc/pam.d/system-auth >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-3. 계정 잠금 임계값 설정" 
echo "1-3. 계정 잠금 임계값 설정" >> $OUT 2>&1
	echo "판단기준: 계정 잠금 임계값이 5 이하의 값으로 설정되어 있는지 확인" >> $OUT 2>&1
	echo "/etc/pam.d/system-auth 파일에 deny 값이 있는지 조회합니다." >> $OUT 2>&1
	cat /etc/pam.d/system-auth |grep deny >> $OUT 2>&1
	echo "" >> $OUT 2>&1

echo "1-4. 패스워드 파일 보호" 
echo "1-4. 패스워드 파일 보호" >> $OUT 2>&1
	echo "판단기준: Shadow 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는지 확인" >> $OUT 2>&1
	echo "/etc/shadow 파일 존재 여부를 확인합니다." >> $OUT 2>&1
if test -f /etc/shadow 
	then 
		echo "/etc/shadow 파일이 존재합니다. Shadow Password를 사용중입니다." >> $OUT 2>&1
		echo "Shadow 파일을 아래에 출력합니다." >> $OUT 2>&1
		echo "************************************************************Shadow File*****************************************************" >> $OUT 2>&1 
		cat /etc/shadow >> $OUT 2>&1
		else
		echo "/etc/shadow 파일이 존재하지 않습니다. Shadow Password를 사용중이지 않습니다." >> $OUT 2>&1
	fi
	echo "/passwd 파일을 모두 출력합니다." >> $OUT 2>&1
	echo "**************************************************************Passwd******************************************************" >> $OUT 2>&1
	cat /etc/passwd >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-5. root 이외의 UID가 0 금지"
echo "1-5. root 이외의 UID가 0 금지" >> $OUT 2>&1
	echo "판단기준: root 계정과 동일한 UID를 갖는 계정이 존재하는지 확인" >> $OUT 2>&1
	echo "Passwd 파일을 출력합니다." >> $OUT 2>&1
	echo "**************************************************************Passwd******************************************************" >> $OUT 2>&1
	cat /etc/passwd >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-6. root 계정 su 제한" 
echo "1-6. root 계정 su 제한" >> $OUT 2>&1
	echo "판단 기준: pam.wheel.so 로드 여부 확인" >> $OUT 2>&1
	cat /etc/pam.d/su |grep 'pam_wheel.so' >> $OUT 2>&1
	echo "Group 파일을 출력합니다." >> $OUT 2>&1
	echo "**************************************************************Group******************************************************" >> $OUT 2>&1
	cat /etc/group >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-7. 패스워드 최소 길이 설정"
echo "1-7. 패스워드 최소 길이 설정" >> $OUT 2>&1
	echo "판단기준: 패스워드 최소 사용기간(PASS_MIN_DAYS = 8 이상으로 되있는지 확인)" >> $OUT 2>&1
	echo "************************************************************login.defs******************************************************" >> $OUT 2>&1 
	cat /etc/login.defs >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-8. 패스워드 최대 사용기간 설정"  
echo "1-8. 패스워드 최대 사용기간 설정" >> $OUT 2>&1
	echo "판단기준: 패스워드 최대 사용기간(PASS_MAX_DAYS = 90 이하로 되어 있는지 확인)" >> $OUT 2>&1
	echo "************************************************************login.defs******************************************************" >> $OUT 2>&1 
	cat /etc/login.defs >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-9. 패스워드 최소 기간 설정" 
	echo "1-9. 패스워드 최소 기간 설정" >> $OUT
	echo "판단기준: 패스워드 최소 사용기간(PASS_MIN_DAYS = 1로 되어 있는지 확인)" >> $OUT 2>&1
	echo "************************************************************login.defs******************************************************" >> $OUT 2>&1 
	cat /etc/login.defs >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-10. 불필요한 계정 제거" 
echo "1-10. 불필요한 계정 제거" >> $OUT 2>&1
	echo "판단기준: 서버 운용에 불필요한 계정이 존재하는지 확인" >> $OUT 2>&1
	echo "/passwd 파일을 출력합니다.." >> $OUT 2>&1
	echo "**************************************************************Passwd******************************************************" >> $OUT 2>&1
	cat /etc/passwd >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-11. 관리자 그룹에 최소한의 계정 포함"
echo "1-11. 관리자 그룹에 최소한의 계정 포함" >> $OUT 2>&1
	echo "판단기준: 관리자 그룹에 불필요한 계정이 등록되어 있는지 확인" >> $OUT 2>&1
	echo "root, wheel, system 그룹 정보를 출력합니다." >> $OUT 2>&1
	grep -E "root" /etc/group >> $OUT 2>&1
	grep -E "system" /etc/group >> $OUT 2>&1
	grep -E "wheel" /etc/group >> $OUT 2>&1
	echo "쉘을 사용중인 계정의 정보를 출력합니다." >> $OUT 2>&1
	echo "**************************************************************Passwd******************************************************" >> $OUT 2>&1
	cat /etc/passwd >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-12. 계정이 존재하지 않는 GID 금지" 
echo "1-12. 계정이 존재하지 않는 GID 금지" >> $OUT 2>&1
	echo "판단기준: 시스탬 관리나 운용에 불필요한 그룹이 삭제 되어 있는지 확인" >> $OUT 2>&1
	echo "***************************************************************Group******************************************************" >> $OUT 2>&1
	cat /etc/group >> $OUT 2>&1
	echo "그룹 내 없는 GID를 가진 계정을 확인하겠습니다." >> $OUT 2>&1
	echo "**************************************************************Passwd******************************************************" >> $OUT 2>&1
	cat /etc/passwd >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "1-13. 동일한 UID 금지"
echo "1-13. 동일한 UID 금지" >> $OUT 2>&1
	echo "판단 기준: 동일한 UID로 설정된 사용자 계정이 존재하는지 확인"
	echo "**************************************************************Passwd******************************************************" >> $OUT 2>&1
	cat /etc/passwd >> $OUT 2>&1
	echo "" >> $OUT 2>&1

echo "1-14. 사용자 shell 점검"
echo "1-14. 사용자 shell 점검" >> $OUT 2>&1
	echo "판단 기준: 동일한 UID로 설정된 사용자 계정이 존재하는지 확인"
	echo "**************************************************************Group******************************************************" >> $OUT 2>&1
	cat /etc/group >> $OUT 2>&1
	echo "" >> $OUT 2>&1

echo "1-15. Session Timeout 설정"
echo "1-15. Session Timeout 설정" >> $OUT 2>&1
	echo "판단기준: Timeout 600sec 이상" >> $OUT 2>&1   
	echo "/etc/profile 파일 내용중, TIMEOUT, TMOUT 항목이 있는지 확인합니다." >> $OUT 2>&1
	grep -E TMOUT /etc/profile >> $OUT 2>&1
	grep -E TIMEOUT /etc/profile >> $OUT 2>&1
	echo "/etc/csh.login 혹은 csh.cshrc 에 TIMEOUT 항목이 있는지 확인합니다." >> $OUT 2>&1
	grep -E TIMEOUT /etc/csh.login >> $OUT 2>&1
	grep -E TIMEOUT /etc/csh.cshrc >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "***************************************************파일 및 디렉토리 관리********************************************************" 

echo "***************************************************파일 및 디렉토리 관리********************************************************" >> $OUT 2>&1

echo "2-1. root 홈, 패스 디렉토리 권한및 패스 설정"
echo "2-1. root 홈, 패스 디렉토리 권한및 패스 설정" >> $OUT 2>&1
	echo "판단기준: PATH 환경변수에 .이 맨 앞이나 중간에 포함되지 않은 경우" >> $OUT 2>&1
	echo "Path 설정을 확인합니다." >> $OUT 2>&1
	# $PATH는 기본변수입니다.
	echo $PATH >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "2-2. 파일 및 디렉토리 소유자 설정"
echo "2-2. 파일 및 디렉토리 소유자 설정" >> $OUT 2>&1
	echo "소유자가 없는 파일을 검색합니다." >> $OUT 2>&1
	find / -nouser -ls >> $OUT 2>&1
	echo "그룹이 없는 파일을 검색합니다." >> $OUT 2>&1
	find / -nogroup -ls >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "2-3. /etc/passwd 파일 소유자 및 권한 설정" 
echo "2-3. /etc/passwd 파일 소유자 및 권한 설정" >> $OUT 2>&1
	echo "판단기준: /etc/passwd 파일의 소유자가 root 이고, 권한이 644 이하인 경우"
	echo "/etc/passwd의 ls 정보를 확인합니다."
	ls -al /etc/passwd >> $OUT 2>&1
	echo ""

echo "2-4. /etc/shadow 파일 소유자 및 권한 설정"
echo "2-4. /etc/shadow 파일 소유자 및 권한 설정" >> $OUT 2>&1
	echo "판단기준: /etc/shadow 파일의 소유자가 root이고 권한이 400인 경우" >> $OUT 2>&1
if test -f /etc/shadow 
	then 
		echo "shadow 파일을 이용중입니다. shadow 파일 권한 및 소유자를 조회하겠습니다." >> $OUT 2>&1
		ls -al /etc/shadow >> $OUT 2>&1
		echo ""
	else 
		echo "이 시스탬은 shadow 파일을 이용하고 있지 않습니다."
		echo ""
fi

echo "2-5. /etc/hosts 파일 소유자 및 권한 설정" 
echo "2-5. /etc/hosts 파일 소유자 및 권한 설정" >> $OUT 2>&1
	echo "판단기준: /etc/hosts 파일 소유자및 권한" >> $OUT 2>&1
if test -f /etc/hosts
then
	echo "/etc/hosts 파일을 이용중입니다." >> $OUT 2>&1
    echo "/etc/hosts 파일의 사용자, 그룹, 권한을 조회합니다." >> $OUT 2>&1
    ls -al /etc/hosts >> $OUT 2>&1
    echo "" >> $OUT 2>&1
else
if test -f /etc/inet/hosts
then
    echo "/etc/inet/hosts를 이용중입니다." >> $OUT 2>&1
    echo "/etc/inet/hosts 파일의 사용자, 그룹, 권한을 조회합니다." >> $OUT 2>&1
    ls -al /etc/inet/hosts >> $OUT 2>&1
    echo "" >> $OUT 2>&1
else
    echo "/etc/hosts 파일 및 /etc/inet/hosts 파일이 아예 존재하지 않습니다." >> $OUT 2>&1
    echo "" >> $OUT 2>&1
fi
echo "2-6. /etc/xinetd.conf 파일 소유자 및 권한 설정"
echo "2-6. /etc/xinetd.conf 파일 소유자 및 권한 설정" >> $OUT 2>&1
if test -f /etc/xinetd.conf
then
    echo "/etc/xinetd.conf 파일 내용을 출력합니다." >> $OUT 2>&1
    cat /etc/xinetd.conf >> $OUT 2>&1
    echo "" >> $OUT 2>&1
else
    echo "/etc/xinetd.conf 파일이 없습니다." >> $OUT 2>&1
    echo "" >> $OUT 2>&1
fi
echo "/etc/xinetd 안의 내용을 조회합니다." >> $OUT 2>&1
ls -al /etc/xinetd.d/* >> $OUT 2>&1
echo "" >> $OUT 2>&1

echo "2-7. /etc/syslog.conf 파일 소유자 및 권한 설정"
echo "2-7. /etc/syslog.conf 파일 소유자 및 권한 설정" >> $OUT 2>&1
    echo "syslog 서비스 현황 확인" >> $OUT 2>&1
    #Centos 7 이상부터는 아래 명령어로 조회가 가능합니다. (6 이하는 불가이므로, 주석처리하여 사용)
    systemctl status syslog >> $OUT 2>&1
    ps -ef | grep 'syslog' | grep -v 'grep' >> $OUT 2>&1
    echo "syslog.conf 파일 확인 (5가지 디렉토리에 지정되어있는 파일을 확인합니다."
if test -f /etc/syslog.conf
then
    echo "/etc/syslog.conf 파일이 존재합니다. 아래 내용을 출력합니다." >> $OUT 2>&1
    cat /etc/syslog.conf >> $OUT 2>&1
    echo ""
fi
if test -f /etc/isyslog.conf
then
    echo "/etc/isyslog.conf 파일이 존재합니다. 아래 내용을 출력합니다." >> $OUT 2>&1
    cat /etc/isyslog.conf >> $OUT 2>&1
    echo ""
fi
if test -f /etc/rsyslog.conf
then
    echo "/etc/rsyslog.conf 파일이 존재합니다. 아래 내용을 출력합니다." >> $OUT 2>&1
    cat /etc/rsyslog.conf >> $OUT 2>&1
    echo ""
fi

echo " "
echo "*****************************************************Finish Check Security Risk*******************************************" 

echo "*****************************************************Finish Check Security Risk*******************************************" >> $OUT 2>&1
