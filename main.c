#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h> //WHOHANG
#include <unistd.h>
#include "./lz4.c" //lz4 압축 라이브러리

#define LOGINTERVAL 50000 // 로그 간격 us
#define FILEOUTINTERVAL 10 // 파일출력 간격 sec

char *logsum = NULL;	 // 전체 로그 메모리
uint64_t logsum_len = 0; // 전체로그 길이
pthread_mutex_t logmutex = PTHREAD_MUTEX_INITIALIZER;
int pipe_c2p[2], pipe_p2c[2]; // 파이프 배열(pipe_child_to_parent, pipe_patent_to_child)
struct pollfd pollfd;		  // parent to child output 감시용 poll
pid_t pid_sqlplus;			  // sqlplus shild process pid

int trylogcopy(char *logdata, uint64_t datalen)
{ // 인자로 받은 스레드 별 로그 데이터를 파일 출력을 위한 전체 로그에 복사 시도

	if (pthread_mutex_trylock(&logmutex) == 0) // 지금 뮤텍스 락 가능하면
	{
		if (logdata == NULL || logdata[0] == '\0') // 복사할 로그 내용이 없으면
			return 0;							   // 복사한 길이 0 반환
		char *logsummary_before = logsum;
		do // 전체로그 할당크기 < 전체로그 길이 + 추가로그 길이 재할당
			logsum = realloc(logsum = logsummary_before, logsum_len + datalen);
		while (logsum == NULL); // 재할당 오류 없을 때까지
		logsummary_before = NULL;

		memcpy(logsum + logsum_len, logdata, datalen); // 스레드 별 로그를 전체로그로 메모리 복사
		logsum_len += datalen - 1;
		logsum[logsum_len] = '\0';

		pthread_mutex_unlock(&logmutex); // 뮤텍스 언락
		return datalen;					 // 복사한 길이 반환
	}
	return 0; // 복사한길이 = 0 반환
}

uint64_t lz4_comp(char *src, char *output)
{ // lz4압축(라이브러리 사용)
	if (src == NULL)
		return 0;
	const uint64_t src_size = (uint64_t)(strlen(src) + 1);
	const int max_dst_size = LZ4_compressBound(src_size); // 압축시 예상 최대 크기 메모리 할당
	if (output == NULL)
	{
		fprintf(stderr, "malloc() error");
		return -1;
	}
	// 압축
	const int compressed_data_size = LZ4_compress_default(src, output, src_size, max_dst_size);
	// 압축 결과 출력
	if (compressed_data_size <= 0)
		fprintf(stderr, "0 or negative result\n");
	if (compressed_data_size > 0)
		fprintf(stderr, "compressed. Ratio: %.2f %\n", (float)compressed_data_size / src_size * 100);
	if (output == NULL)
	{
		fprintf(stderr, "realloc() error");
		return -1;
	}
	// 압축 결과 반환
	return (uint64_t)compressed_data_size;
}

pid_t init_sqlplus_process(int pipe_c2p, int pipe_p2c) // sqlplus shild process
{													   // sqlplus process

	pid_t pid = fork(); // 자식프로세스의 pid를 저장할 변수
	if (pid == 0)		// child proc
	{
		dup2(pipe_c2p, STDOUT_FILENO); // pipec2p(child to parent) 를 표준출력에 덮어쓰기
		dup2(pipe_p2c, STDIN_FILENO);  // pipep2c(parent to child) 를 표준입력에 덮어쓰기
		char *sqlplus_path = NULL;	   // sqlplus binary path
		{							   // get $ORACLE_HOME
			char *oracle_home = NULL;
			FILE *pid_echo = popen("echo -n $ORACLE_HOME", "r"); //$ORACLE_HOME 확인
			char buff[16];
			int buffsize = sizeof(buff) / sizeof(char);
			int buffalloced = 0;
			if (NULL == pid_echo)
			{
				fprintf(stderr, "get  $ORACLE_HOME popen() error");
				return -1;
			}
			while (fgets(buff, buffsize, pid_echo))
			{
				char *oracle_home_before = NULL;
				while (oracle_home == NULL || strlen(oracle_home) + strlen(buff) >= buffalloced) // 처음, 할당 실패, 할당 크기 부족
				{
					oracle_home = (char *)realloc(oracle_home_before = oracle_home, sizeof(char) * (buffalloced += buffsize));
					if (buffalloced == buffsize)
						oracle_home[0] = '\0';
				}
				strncat(oracle_home, buff, strlen(buff)); // 버퍼를 oaracle_home으로 복사
			}
			if (pclose(pid_echo) == -1)
			{
				fprintf(stderr, "pclose() error");
				return -1;
			}
			pid_echo = NULL;

			sqlplus_path = (char *)malloc(sizeof(char) * (strlen(oracle_home) + strlen("/bin/sqlplus") + 1));
			sqlplus_path[0] = 0;

			// sqlplus binary absolute path
			strncat(sqlplus_path, oracle_home, strlen(oracle_home));
			strncat(sqlplus_path, "/bin/sqlplus", strlen("/bin/sqlplus"));
			free(oracle_home);
		}

		// sqlplus 실행
		execl(sqlplus_path, "sqlplus", "-f", "/", "as", "sysdba", NULL);
		// 오류시 에러 출력
		perror("perror\n");
	}
	return pid;
}

char *run_sql(char *sql, int doreturn)
{
	char *ret = NULL;					 // 반환 문자열
	int ret_alloced = 1;				 // 반환 문자열 할당 크기
	static int state;					 // child process state
	char sqlcheckbuff[5] = "\0\0\0\0\0"; // sql 종료 확인 비교 문자열
	int iswritten = 0;					 // 직전에 파이프 씀 플래그
	while (1)
	{
		int readable = poll(&pollfd, 1, 0); //(pollfd, n of fd, waittime ms), 읽을 수 있는 fd 개수 반환
		if (readable == 0)					// 읽을 내용이 없으면
		{
			if (waitpid(pid_sqlplus, &state, WNOHANG) == 0) // child process 가 끝나지 않았으면
			{
				if (iswritten == 0) // 직전에 쓰지 않았으면
				{					// 함수 인가의 sql문을 parent to child 파이프의 input에 쓰기
					write(pipe_p2c[1], sql, strlen(sql));
					write(pipe_p2c[1], "\n", 1);
					iswritten = 1; // 직전에 파이프 씀 플래그 설정
				}
				else if (ret != NULL && strncmp(&ret[strlen(ret) - 5], "SQL>", 4) == 0) // 반환값의 마지막 4글자가 "SQL>"이면
				{
					if (doreturn == 1 && strstr(ret, "ORA-") == NULL) // 리턴해야하고 오류코드 없으면
					{
						ret[(strlen(ret) - 6)] = '\0';							  // 마지막 "SQL> " 직전에 '\0'쓰기
						ret = realloc(ret, sizeof(char) * (strlen(ret) - 6 + 1)); // "SQL> " 제외한 글자만큰 메모리 재할당
						return ret;
					}
					else
					{
						free(ret);
						return NULL;
					}
				}
			}
			else
				break; // sqlplus 프로세스 종료됐을 때
			continue;
		}
		else if (pollfd.revents & (POLLIN | POLLERR) || (strncmp(sqlcheckbuff, "SQL>", 4) == 0))
		{ // 읽을 내용이 있고 POLLIN | POLLERR 이벤트 발생이면

			char tmp; // 파이프에서 읽은 문자
			// poll fd(== child to parent output)읽고 내용이 없으면 파이프 닫기
			if (read(pollfd.fd, &tmp, sizeof(char)) < 0)
			{
				close(pollfd.fd);
				pollfd.fd = -1;
				break;
			}
			else // 읽을 내용이 있으면
			{
				if (iswritten == 1)
				{ // 직전에 파이프에 썼으면 메모리 재할당으로 크기 늘리기
					char *ret_before = NULL;
					while (ret == NULL || strlen(ret) + 1 >= ret_alloced) // 처음, 할당 실패, 할당 크기 부족
					{
						ret = (char *)realloc(ret_before = ret, sizeof(char) * (++ret_alloced));
						if (ret_alloced == 2) // 처음이면
							ret[0] = ret[1] = '\0';
					}
					int retlen = strlen(ret);
					ret[retlen] = tmp;
					ret[retlen + 1] = '\0';
				}
			}
			for (int i = 0; i < 4; i++) // sql종료 확인용 문자열 한칸씩 이동 후 읽은 문자 추가
				sqlcheckbuff[i] = sqlcheckbuff[i + 1];
			sqlcheckbuff[4] = tmp;
		}
	}
	return NULL;
}

void *t_ps(void *state)
{
	char buff[4194304] = {'\0'}; // 읽기 버퍼 4KiB
	uint64_t buffsize = sizeof(buff) / sizeof(char);
	const uint64_t interval_log_us = LOGINTERVAL;

	char *syslogdata = NULL;	 // 시스템정보 로그
	uint64_t logsizealloced = 0; // 할당된 메모리 크기
	uint64_t sysloglen = 0;		 // 로그 길이

	int issaved = 0;				 // 직전에 저장 플래그
	struct timeval tv_start, tv_now; // 실행시간 계산용
	uint64_t sleeptime;				 // 계산한 usleep 시간
	uint64_t cnt = 0;				 // 루프 실행 카운트

	FILE *fp_pidstat, *fp_loadavg;

	uint64_t test_minsleeptime = LOGINTERVAL;
	uint64_t test_sleep_avg = 0;

	gettimeofday(&tv_start, NULL); // 시작 시간 측정
	while (*(int *)state > 0)
	{
		{
			// /proc/loadavg 파일 내용으로 부하 확인
			fp_loadavg = fopen("/proc/loadavg", "r");

			if (NULL == fp_loadavg)
			{
				fprintf(stderr, "fopen() error");
				return NULL;
			}

			// 현재 시각 추가
			gettimeofday(&tv_now, NULL);
			uint64_t bufflen = sprintf(buff, "\n\n!%10lu.%06lu\n", tv_now.tv_sec, tv_now.tv_usec); // UNIXTIME.MICROSECOND "%10lu.%06lu\n"
			if ((bufflen += fread(buff + bufflen, sizeof(char), buffsize, fp_loadavg)) <= 0)	   // 파일 내용 버퍼로 읽기
			{
				fprintf(stderr, "fread() error");
				return NULL;
			}

			buff[bufflen] = '\n';
			buff[bufflen++] = '\0';
			char *log_before;
			while (syslogdata == NULL || sysloglen + bufflen >= logsizealloced) // 처음, 할당 실패, 할당 크기 부족
			{
				syslogdata = (char *)realloc(log_before = syslogdata, sizeof(char) * (logsizealloced += buffsize));
				if (logsizealloced == buffsize)
					syslogdata[0] = '\0';
			}
			strncpy(syslogdata + sysloglen, buff, bufflen); // 버퍼내용 시스템정보 로그 메모리로 복사
			sysloglen += bufflen - 1;
			syslogdata[sysloglen] = '\0';

			if (fclose(fp_loadavg) == -1)
			{
				fprintf(stderr, "fclose() error");
				return NULL;
			}
			fp_loadavg = NULL;
		} // get /proc/loadavg end

		{ // pidstat 으로 프로세스 별 cpu, mem, disk 사용량 읽기
			// fp_pidstat = popen("pidstat -d -u -l -U -r|awk 'NR>2 && substr($0,index($0,$8))!~/vscode/{print(substr($0,index($0,$3)))}'", "r");
			fp_pidstat = popen("pidstat -d -u -l -U -r|awk 'NR>2{print(substr($0,index($0,$3)))}'", "r");
			if (NULL == fp_pidstat)
			{
				fprintf(stderr, "popen() error");
				return NULL;
			}
			while (fgets(buff, buffsize, fp_pidstat))
			{
				uint64_t bufflen = strlen(buff);
				char *log_before;
				while (syslogdata == NULL || sysloglen + bufflen >= logsizealloced) // 처음, 할당 실패, 할당 크기 부족
				{
					syslogdata = (char *)realloc(log_before = syslogdata, sizeof(char) * (logsizealloced += buffsize));
					if (logsizealloced == buffsize)
						syslogdata[0] = '\0';
				}
				strncpy(syslogdata + sysloglen, buff, bufflen); // 버퍼를 시스템정보 로그 메모리로 복사하고
				sysloglen += bufflen;							// 로그 길이 계산
				syslogdata[sysloglen] = '\0';
			}
			if (pclose(fp_pidstat) == -1)
			{
				fprintf(stderr, "pclose() error");
				return NULL;
			}
			fp_pidstat = NULL;
		} // get pidstat output end

		// 시스템정보 로그 메모리 전체 로그 메모리로 복사 시도
		if (trylogcopy(syslogdata, sysloglen) == sysloglen)
		{						  // 복사 성공한 길이가 전체 길이와 같으면
			sysloglen = 0;		  // 시스템정보 로그길이 초기화
			syslogdata[0] = '\0'; // 시스템정보 로그내용 초기화
		}

		// 로그 간격 - 실행 시간 으로 usleep 계산
		gettimeofday(&tv_now, NULL); // 현재시간
		time_t etime = ((tv_now.tv_sec - tv_start.tv_sec) * 1000000 + (tv_now.tv_usec - tv_start.tv_usec));
		sleeptime = (interval_log_us * ++cnt > etime) ? interval_log_us * cnt - etime : 0;

		// if (sleeptime < test_minsleeptime)
		// 	test_minsleeptime = sleeptime;

		// test_sleep_avg += sleeptime;
		// test_sleep_avg /= 2;

		// 실행 정보 출력
		// 실행시간, sleep 시간, 설정 로그 간격, 메모리 할당 크기, 최고 sleep 시간 등
		// fprintf(stderr, "%8ld : PS  LOG : %4lu /%4lu /%4lu ms %8lums %8luMB alloc min : %8u us avg : %4lu ms\n",
		// 		0, (interval_log_us - sleeptime) / 1000, sleeptime / 1000, interval_log_us / 1000, etime / 1000, logsizealloced >> 20, test_minsleeptime, test_sleep_avg / 1000); // 카운터,시간 출력

		// if (test_minsleeptime <= 10)
		// 	test_minsleeptime = LOGINTERVAL;

		if (sleeptime > 0)
			usleep(sleeptime);
	}

	return (void *)1;
}

void *t_shm(void *state)
{
	char buff[4194304] = {'\0'}; // sqlplus 읽기 버퍼 4KiB
	uint64_t buffsize = sizeof(buff) / sizeof(char);

	const uint64_t interval_log_us = LOGINTERVAL; // 로그 간격

	char *logdata = NULL;		 // 현재 스레드 로그 메모리
	uint64_t logsizealloced = 0; // 할당된 로그 메모리 크기
	uint64_t loglen = 0;		 // 로그 길이

	struct timeval tv_start, tv_now;		  // 스레드 시작시간, 루프 실행시간
	uint64_t sleeptime;						  // 계산한 usleep할 시간
	uint64_t test_minsleeptime = LOGINTERVAL; // 실행시간 초과 테스트용 최소 sleep 시간
	uint64_t test_sleep_avg = 0;			  // sleep평균
	uint64_t cnt = 0;						  // 실행 카운트

	// pipe child(sqlplus) to parent(this), pipe parent to child
	pipe(pipe_c2p), pipe(pipe_p2c); // pipe_c2p[0] <== pipe_c2p[1], pipe_p2c[0] <== pipe_p2c[1]

	// waitpid()용 pid wjwkd
	pid_sqlplus = init_sqlplus_process(pipe_c2p[1], pipe_p2c[0]);

	memset(&pollfd, 0, sizeof(pollfd)); // 메모리 초기화
	pollfd.fd = pipe_c2p[0];			// child sqlplus 프로세스에서 읽는 파이프 감시를 위해 poll 설정
	pollfd.events = POLLIN | POLLPRI;	// 감시할 이벤트 설정
	// 이후로 poll fd io

	{ // init sql*plus output
		run_sql("SET SERVEROUTPUT OFF", 0);
		run_sql("startup", 0);
		run_sql("set linesize 1024", 0);
		run_sql("set echo off", 0);
		run_sql("set pagesize 0", 0);
		run_sql("set feedback off", 0);
		run_sql("set tab off", 0);
		run_sql("SET SERVEROUTPUT ON", 0);
	}

	gettimeofday(&tv_start, NULL); // 루프 시작시간

	while (*(int *)state > 0)
	{
		int *nattach = NULL;
		int nattach_cnt = 0;
		static int *nattach_before = NULL;
		static int nattach_cnt_before = 0;

		static long long int ksusesql_offset = -1;
		if (nattach_before == NULL) // 처음 한번만 실행
		{
			{ // 오라클 세션에서 sql offset 구하기
				run_sql("column kqfconam format a10", 0);
				char *ksusesql_offset_str = run_sql("select co.kqfcooff from x$kqfta ta, x$kqfco co where co.kqfcotab = ta.indx and ta.kqftanam = 'X$KSUSE' and co.kqfconam = 'KSUSESQL';", 1);
				ksusesql_offset = atoi(ksusesql_offset_str);
				free(ksusesql_offset_str);
			}
		}

		{ // ipcs 내용 저장
			const char ipcsstr[] = "ipcs -mb | awk 'NR>=4{print $2\" \"$6}'";
			FILE *fp_ipcs = popen(ipcsstr, "r"); // ipcs -mb fp

			if (NULL == fp_ipcs)
			{
				fprintf(stderr, "ipcs popen() error");
				return (void *)-1;
			}
			while (fgets(buff, buffsize, fp_ipcs))
			{
				int i, shmid;
				sscanf(buff, "%d %d", &i, &shmid);

				int *nattach_alloc_before = nattach;
				while (nattach == NULL) // 처음 == NULL 또는 realloc 오류 == NULL
					nattach = (int *)realloc(nattach = nattach_alloc_before, sizeof(int) * i);

				nattach[i] = shmid;
				if (i > nattach_cnt)
					nattach_cnt = i;
			}
			if (pclose(fp_ipcs) == -1)
			{
				fprintf(stderr, "ipcs pclose() error");
				return (void *)-1;
			}
			fp_ipcs = NULL;
		}

		static long long unsigned int *sessions_ptr = NULL; // 세션목록 포인터
		static int sessions_cnt = 0;						// 세션 카운트

		static int fixed_shmid = -1;
		static long long int fixed_memaddr = 0;
		static int var_shmid = -1;
		static long long int var_memaddr = 0;
		void *fixed_addr_access = NULL;
		void *var_addr_access = NULL;

		if (!(nattach_cnt == nattach_cnt_before && memcmp(nattach, nattach_before, nattach_cnt) == 0))
		// shared memory 개수나 nattach 개수가 이전과 같지 않으면
		{
			{
				char *sessions_str = run_sql("select addr from x$ksuse;", 1); // 세션주소 목록
				char *sessions_str_line = strtok(sessions_str, "\n");		  // 목록 한줄
				while (sessions_str_line != NULL)
				{ // 목록 내용이 더 있는 동안 메모리 재할당하여 추가
					sessions_ptr = realloc(sessions_ptr, (sessions_cnt + 1) * sizeof(long long unsigned int));
					sessions_ptr[sessions_cnt] = strtoull(sessions_str_line, NULL, 16);
					sessions_str_line = strtok(NULL, "\n");
					sessions_cnt++; // 세션 카운트 추가
				}
				free(sessions_str);
				sessions_str = NULL;
			}
			nattach_before = nattach;
			nattach_cnt_before = nattach_cnt;
		}

		{ // shared memory 'Fixed Size', 'Variable Size' shmid, 주소 주하기
			char *fixed_addr_str = run_sql("select \"SEG_START ADDR\" from x$ksmssinfo where \"AREA NAME\" = 'Fixed Size';", 1);
			fixed_memaddr = strtoull(fixed_addr_str, NULL, 16);
			free(fixed_addr_str);
			char *fixed_shmid_str = run_sql("select \"SHMID\" from x$ksmssinfo where \"AREA NAME\" = 'Fixed Size';", 1);
			fixed_shmid = atoi(fixed_shmid_str);
			free(fixed_shmid_str);

			char *var_addr_str = run_sql("select \"SEG_START ADDR\" from x$ksmssinfo where \"AREA NAME\" = 'Variable Size';", 1);
			var_memaddr = strtoull(var_addr_str, NULL, 16);
			free(var_addr_str);
			char *var_shmid_str = run_sql("select \"SHMID\" from x$ksmssinfo where \"AREA NAME\" = 'Variable Size';", 1);
			var_shmid = atoi(var_shmid_str);
			free(var_shmid_str);
		}

		{ // shared memory 'Fixed Size', 'Variable Size' attach
			fixed_addr_access = shmat(fixed_shmid, (void *)fixed_memaddr, SHM_RDONLY);
			var_addr_access = shmat(var_shmid, (void *)var_memaddr, SHM_RDONLY);
		}

		// mem dump ///////////////////////////////////////////////////////////
		// fprintf(stderr, "var shmid:    %i\n", var_shmid);
		// var_addr_access = shmat(var_shmid, (void *)var_memaddr, SHM_RDONLY);
		// if (var_addr_access != (void *)-1)
		//{
		//	fprintf(stderr, "var address:    %p %d \n", var_addr_access, var_addr_access);
		// }
		// else
		//{
		//	fprintf(stderr, "Failed to attach var size \n");
		//	exit(EXIT_FAILURE);
		// }
		// char *mem = (char *)malloc(1593835520);
		// memcpy(mem, var_addr_access, 1593835520);
		// FILE *fpvar = fopen("memdump", "w");
		// fwrite(mem, sizeof(char), 1593835520, fpvar);
		// fclose(fpvar);
		/////////////////////////////////////////////////////////////

		// 처음 한번만 실행 sql text offset
		static int sqltext_offset = -1;
		while (sqltext_offset < 0)
		{													  // 테스트용 sql 실행하여 세션에서 실행중인 sql구문 offset 찾기
			char shmtestsql[90];							  // 테스트 sql
			static int session_sleeptime_ms = 5;			  // 테스트 sql 실행(sleep)시간
			static int session_sleeptime_interval_us = 65000; // 실행 후 메모리 확인 전 대기시간(개발 환경 상 적정시간으로 설정)

			// test sql
			snprintf(shmtestsql, sizeof(shmtestsql), "echo -e 'begin//SHMTEST*/dbms_session.sleep(0.%03d);end;\n/' | sqlplus / as sysdba", session_sleeptime_ms);
			FILE *fp_testsql = NULL;
			if (sqltext_offset < 0)
			{
				fp_testsql = popen(shmtestsql, "r");   // 테스트 sqlplus 실행
				usleep(session_sleeptime_interval_us); // 세션 메모리 확인까지 대기
				if (NULL == fp_testsql)
				{
					fprintf(stderr, "popen test sql error");
					return NULL;
				}
			}

			for (int i = 0; i < sessions_cnt; i++) // 오라클 세션 탐색
			{
				if (*(unsigned long int *)(sessions_ptr[i] + ksusesql_offset))
				{ // 세션 내용이 있으면
					int alloc_size = sessions_ptr[i + 1] + ksusesql_offset - (sessions_ptr[i] + ksusesql_offset);
					char *temp = (char *)malloc(alloc_size);
					memcpy(temp, (void *)(*(unsigned long int *)(sessions_ptr[i] + ksusesql_offset)), alloc_size);

					{
						const static char teststr[] = "//SHMTEST*/"; // 찾을 테스트 sql 내용
						const int teststrlen = strlen(teststr);
						for (int j = 0; j < alloc_size - teststrlen; j++)
							if (memcmp(temp + j, teststr, teststrlen) == 0)
							{
								sqltext_offset = j - strlen("begin"); // sql offset
								break;
							}
						if (sqltext_offset > -1)
							break;
					}
					free(temp);
				}
				if (sqltext_offset > -1)
					break;
			}

			if (sqltext_offset < 0) // 못찾았으면 다음에는 1000us 느리게
			{
				session_sleeptime_ms++;
				session_sleeptime_interval_us += 1000;
			}
			// else // 찾았으면 다음에 100us 빨리
			// {
			// 	session_sleeptime_ms--;
			// 	session_sleeptime_interval_us -= 100;
			// }

			// pclose
			if (fp_testsql != NULL && pclose(fp_testsql) == -1)
			{
				fprintf(stderr, "ipcs pclose() error");
				return NULL;
			}
			fp_testsql = NULL;

			gettimeofday(&tv_start, NULL); // sql text offset 탐색을 했으면 시작시간 다시 설정
		}

		// log print time
		gettimeofday(&tv_now, NULL);
		uint64_t bufflen = sprintf(buff, "\n!%10lu.%06lu\n", tv_now.tv_sec, tv_now.tv_usec); // UNIXTIME.MICROSECOND "%10lu.%06lu\n"

		int running_sql_cnt = 0;
		for (int i = 0; i < sessions_cnt; i++) // 세션 탐색
		{
			if (*(unsigned long int *)(sessions_ptr[i] + ksusesql_offset)) // 내용이 있으면
			{
				running_sql_cnt++; // 실행중 sql 카운트 추가

				// sql 정보 출력
				bufflen += sprintf(
					buff + bufflen,
					"SID: %4i, saddr: %16p, sql_address: %16p, cursor address: %16p, text address: %16p\n",
					i + 1,
					sessions_ptr[i],
					sessions_ptr[i] + ksusesql_offset,
					*(unsigned long int *)(sessions_ptr[i] + ksusesql_offset),
					*(unsigned long int *)(sessions_ptr[i] + ksusesql_offset) + sqltext_offset);
				bufflen += sprintf(buff + bufflen, "%s\n", (char *)(*(unsigned long int *)(sessions_ptr[i] + ksusesql_offset) + sqltext_offset));
			}
		}

		char *log_before;
		while (logdata == NULL || loglen + bufflen >= logsizealloced) // 처음, 할당 실패, 할당 크기 부족
		{
			logdata = (char *)realloc(log_before = logdata, sizeof(char) * (logsizealloced += buffsize));
			if (logsizealloced == buffsize)
				logdata[0] = '\0';
		}
		strncpy(logdata + loglen, buff, bufflen); // 버퍼를 공유메모리 로그 버퍼로 복사
		loglen += bufflen - 1;
		logdata[loglen] = '\0';

		if (trylogcopy(logdata, loglen) == loglen) // 전체 로그로 복사 성공시 공유메모리 로그 내용 초기화
		{
			loglen = 0;
			logdata[0] = '\0';
		}

		// 공유메모리 dettach
		shmdt(fixed_addr_access);
		shmdt(var_addr_access);

		// 로그 간격 - 실행 시간 으로 usleep 계산
		gettimeofday(&tv_now, NULL);
		time_t etime = ((tv_now.tv_sec - tv_start.tv_sec) * 1000000 + (tv_now.tv_usec - tv_start.tv_usec));
		sleeptime = (interval_log_us * ++cnt > etime) ? interval_log_us * cnt - etime : 0;

		// 실행 정보 출력
		if (sleeptime < test_minsleeptime)
			test_minsleeptime = sleeptime;

		test_sleep_avg += sleeptime;
		test_sleep_avg /= 2;

		// 실행시간, sleep 시간, 설정 로그 간격, 메모리 할당 크기, 최고 sleep 시간 등
		// fprintf(stderr, "%8ld : SHM LOG : %4lu /%4lu /%4lu ms %8lums %8luMB alloc min : %8u us avg : %4lu ms ",
		// 		0, (interval_log_us - sleeptime) / 1000, sleeptime / 1000, interval_log_us / 1000, etime / 1000, logsizealloced >> 20, test_minsleeptime, test_sleep_avg / 1000); // 카운터,시간 출력
		fprintf(stderr, "SHM THREAD: %4lu /%4lu ms, sleep :%4lu ms, running :%8lums, allocated :%4luMB, min sleep : %8u us, avg sleep : %4lu ms ",
				(interval_log_us - sleeptime) / 1000, interval_log_us / 1000, sleeptime / 1000, etime / 1000, logsizealloced >> 20, test_minsleeptime, test_sleep_avg / 1000); // 카운터,시간 출력

		// 실행중인 sql 개수
		fprintf(stderr, "running sqls : %d\n", running_sql_cnt);

		if (test_minsleeptime <= 10)
			test_minsleeptime = LOGINTERVAL;

		if (sleeptime > 0)
			usleep(sleeptime);
	}

	// on thread end
	kill(pid_sqlplus, SIGKILL); // kill sqlplus process
	while (waitpid(pid_sqlplus, NULL, 0) <= 0)
		; // wait sqlplus process return
	return (void *)2;
}

void *t_filewrite(void *state)
{ // file save
	const time_t interval_fileout_sec = FILEOUTINTERVAL;
	struct timeval tv_save;
	int issaved = 0;
	while (*(int *)state > 0)
	{
		if (logsum == NULL || logsum_len <= 0) // 전체 로그에 저장된 로그가 없으면
			continue;
		gettimeofday(&tv_save, NULL); // 루프 시작시간
		if (tv_save.tv_sec % interval_fileout_sec == 0 && issaved == 0 && logsum_len > 0)
		{ // 루프 시작시간이 파일출력 간격에 맞고
			// 직전에 파일출력을 하지 않았고
			// 전체 로그 내용이 있으면
			char filename_comp[20];								 // 출력 파일 이름
			sprintf(filename_comp, "%lu_c.log", tv_save.tv_sec); // 루프 시작시간으로 파일 이름 만들기
			fprintf(stderr, "fileout : %s\n", filename_comp);	 // 파일 이름 출력

			FILE *fp_comp = fopen(filename_comp, "wb"); // 출력파일 포인터
			if (fp_comp == NULL)
			{
				fprintf(stderr, "fopen() error");
				return NULL;
			}

			pthread_mutex_lock(&logmutex); // 전체 로그 메모리 뮤텍스 락

			void *output = malloc(LZ4_compressBound(logsum_len));	   // 압축시 최대크기 예상값 메모리 할당
			const uint64_t compressed_size = lz4_comp(logsum, output); // 압축

			uint64_t logsize = (uint64_t)(logsum_len + 1);
			fwrite(&logsize, sizeof(uint64_t), 1, fp_comp); // 압축파일의 처음 64비트 파일크기 쓰기
			fwrite(output, compressed_size, 1, fp_comp);	// 그 이후 압축내용 쓰기

			free(output);

			if (fclose(fp_comp) == -1)
			{
				fprintf(stderr, "fclose() error");
				return NULL;
			}

			free(logsum);					 // 전체 로그 메모리 해제
			logsum = NULL;					 // 초기화
			logsum_len = 0;					 // 초기화
			pthread_mutex_unlock(&logmutex); // 전체 로그 메모리 뮤텍스 해제
			issaved = 1;					 // 직전에 저장함 플래그 설정
		}
		else if (issaved == 1 && tv_save.tv_sec % interval_fileout_sec != 0)
			// 직전에 저장했고
			// 저장 간격 시간에 맞지 않으면
			issaved = 0; // 직정에 저장함 플래그 해제

		gettimeofday(&tv_save, NULL);
		// 파일 저장 간격만큼 usleep()
		usleep(tv_save.tv_sec % interval_fileout_sec * 1000 + tv_save.tv_usec);
	}
	// file out end
	return (void *)3;
}

SSL_CTX *initctx(char sc)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	if (sc == 's') // 서버용 메소드
		method = (SSL_METHOD *)TLSv1_2_server_method();
	else if (sc == 'c') // 클라이언트용 메소드
		method = (SSL_METHOD *)TLSv1_2_client_method();

	ctx = SSL_CTX_new(method); // 메소드로 컨텍스트 생성
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		return (SSL_CTX *)-1;
	}
	return ctx;
}

int LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{ // 인증서 파일 불러오기
	if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
	{
		ERR_print_errors_fp(stderr);
		return 1;
	}

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		return 1;
	}

	// set the local certificate from CertFile
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return 1;
	}
	// set the private key from KeyFile
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return 1;
	}
	// verify private key
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify_depth(ctx, 4);
}

int showcerts(SSL *ssl)
{
	int ret = -1;
	X509 *cert;
	cert = SSL_get_peer_certificate(ssl); // 서버 인증서 가져오기
	if (cert != NULL)					  // 인증서가 있으면
	{
		X509_STORE_CTX *ctx = X509_STORE_CTX_new();
		X509_STORE *store = X509_STORE_new();
		X509_STORE_add_cert(store, cert);			 // Copy a certificate to X509_STORE 로 인증서 복사
		X509_STORE_CTX_init(ctx, store, cert, NULL); // X509_STORE_CTX 를 검증을 위해 설정

		// X.509 인증서 검증
		if (X509_verify_cert(ctx) == 1)
			ret = 0;
		else
			ret = 1;
	}
	else // 인증서가 없으면
		fprintf(stderr, "No cert\n");

	X509_free(cert);
	return ret;
}

int open_serv_sock(int port)
{
	int server_sock;
	struct sockaddr_in addr;
	server_sock = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		perror("can't bind port");
		return -1;
	}
	if (listen(server_sock, 10) != 0)
	{
		perror("Can't configure listening port");
		return -1;
	}
	return server_sock;
}

int open_client_sock(const char *hostname, int port)
{
	int client_sock;
	struct hostent *host;
	struct sockaddr_in addr;
	if ((host = gethostbyname(hostname)) == NULL)
	{
		perror(hostname);
		abort();
	}
	client_sock = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	addr.sin_addr.s_addr = *(host->h_addr_list[0]);
	if (connect(client_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		close(client_sock);
		perror(hostname);
		return -1;
	}
	return client_sock;
}

void sned_to_datagather(char *timestamp_start, char *timestamp_end)
{
	int client_sock;
	char *datagather_hostname = "127.0.0.1";
	int datagather_port = 7001;

	client_sock = open_client_sock(datagather_hostname, datagather_port);
	if (client_sock != -1)
	{
		SSL *ssl;
		SSL_CTX *ctx;
		char buff[1024];
		int recvlen = -1;

		SSL_library_init();								 // SSL 초기화
		ctx = initctx('c');								 // 클라이언스 메소드로 컨텍스트 설정
		LoadCertificates(ctx, "cert2.pem", "cert2.pem"); // data gather용 인증서
		ssl = SSL_new(ctx);								 // 컨텍스트로 SSL 생성
		SSL_set_fd(ssl, client_sock);					 // 클라이언트 소켓에 SSL 설정
		if (SSL_connect(ssl) == -1)						 // 연결
			ERR_print_errors_fp(stderr);
		else // 파일 전송
		{
			if (showcerts(ssl) == 0) // 서버 인증서 검증
				fprintf(stderr, "DG cert ok\n");
			else
				fprintf(stderr, "DG cert fail\n");
			char valid_msg[29];
			sprintf(valid_msg, "/*TEST%s%s*/", timestamp_start, timestamp_end); // 메세지 형식 + timestamp

			SSL_write(ssl, valid_msg, strlen(valid_msg));

			fprintf(stderr, "timestamp : %s - %s\n", timestamp_start, timestamp_end); // 전송할 timestamp 출력
			char buff[1024] = {0};
			DIR *dir_info;
			struct dirent *dir_entry;
			dir_info = opendir("."); // 현재 디렉토리를 열기
			if (NULL != dir_info)
			{
				while (dir_entry = readdir(dir_info)) // 디렉토리 안에 있는 모든 파일과 디렉토리 출력
				{
					int len_d_name = strlen(dir_entry->d_name);
					if (len_d_name > 4 && strncmp(&dir_entry->d_name[len_d_name - 6], "_c.log", 6) == 0 && strncmp(timestamp_start, dir_entry->d_name, 10) <= 0 && strncmp(timestamp_end, dir_entry->d_name, 10) >= 0)
					{												//_c.log 이고 timestamp_start 이후면 파일내용 전송
						fprintf(stderr, "%s\n", dir_entry->d_name); // 전송할 파일 이름 출력

						FILE *fp = fopen(dir_entry->d_name, "r");
						fseek(fp, 0, SEEK_END);
						uint64_t filesize = ftell(fp); // 파일 크기
						fseek(fp, 0, SEEK_SET);
						char *data = (char *)malloc(sizeof(char) * filesize);
						fread(data, sizeof(char), filesize, fp);

						char *fileinfo;
						SSL_write(ssl, dir_entry->d_name, len_d_name); // 파일 이름(기록시간 포함)
						SSL_write(ssl, &filesize, sizeof(uint64_t));   // 파일 크기
						SSL_write(ssl, data, filesize);				   // 파일 내용
						fclose(fp);
						free(data);
					}
				}
				closedir(dir_info);
			}
		}
		SSL_free(ssl);		// release connection state
		close(client_sock); // close socket
		SSL_CTX_free(ctx);	// release context
	}
}

void *t_ssl(void *state)
{
	SSL_CTX *ctx;
	int server;
	int port = 5080;

	SSL_library_init(); // SSL library 초기화

	ctx = initctx('s');								 // 서버 메소드로 컨텍스트 초기화
	LoadCertificates(ctx, "cert1.pem", "cert1.pem"); // load certs

	{ // 요청서버 소켓 생성
		struct sockaddr_in addr;
		server = socket(PF_INET, SOCK_STREAM, 0);
		bzero(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = INADDR_ANY;
		while (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0)
			perror("can't bind port");
		if (listen(server, 10) != 0)
			perror("Can't configure listening port");
	}

	struct sockaddr_in addr;
	SSL *ssl;
	struct linger solinger = {1, 2}; // 소켓 옵션 설정 time_wait true, time_wait = 2sec
	while (1)
	{
		socklen_t len = sizeof(addr);
		int request_server = accept(server, (struct sockaddr *)&addr, &len);

		// 소켓 옵션 설정
		if (setsockopt(request_server, SOL_SOCKET, SO_LINGER, &solinger, sizeof(struct linger)) == -1)
			perror("setsockopt error");

		fprintf(stderr, "Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx); // 컨텍스트로 SSL설정
		char *timestamp_start = NULL;
		char *timestamp_end = NULL;
		SSL_set_fd(ssl, request_server); // 소켓에 SSL설정
		{
			char buff[1024] = {0};
			int recvlen;
			const char valid_msg_start[] = "/*TEST"; // 확인용 메세지
			const char valid_msg_end[] = "*/";
			if (SSL_accept(ssl) == -1) // SSL accept
				ERR_print_errors_fp(stderr);
			else
			{
				if (showcerts(ssl) == 1) // X.509 인증서 검증
					fprintf(stderr, "Cert fail\n");
				else
				{
					fprintf(stderr, "Cert ok\n");
					recvlen = SSL_read(ssl, buff, sizeof(buff) - 1); // req_client 로부터 수신
					buff[recvlen] = '\0';
					fprintf(stderr, "Client msg: \"%s\"\n", buff); // 수신 메세지
					if (recvlen <= 0)
						ERR_print_errors_fp(stderr);
					else if (strncmp(buff, valid_msg_start, strlen(valid_msg_start)) || strncmp(&buff[recvlen - strlen(valid_msg_end)], valid_msg_end, strlen(valid_msg_end)))
					{ // 메세지 앞, 뒤 확인, 오류
						fprintf(stderr, "Invalid msg\n");
						SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); // send error reply
					}
					else // 메세지 앞, 뒤 확인, 정상
					{
						SSL_write(ssl, buff, strlen(buff)); // echo

						// timestamp_start, timestamp_end 나누기
						strtok(buff, "_");
						timestamp_start = (char *)malloc(sizeof(char) * 11);
						timestamp_start[10] = '\0';
						timestamp_end = (char *)malloc(sizeof(char) * 11);
						timestamp_end[10] = '\0';
						char *timestamp_str = strtok(NULL, "*");
						memcpy(timestamp_start, timestamp_str, 10);
						memcpy(timestamp_end, timestamp_str + 10, 10);
					}
				}
			}
		}
		int sock_fd = SSL_get_fd(ssl);						  // 클라이언트 소켓
		SSL_free(ssl);										  // SSL 해제
		close(sock_fd);										  // 소켓 닫기
		if (timestamp_start != NULL && timestamp_end != NULL) // 타임스탬프 시작, 끝이 있으면
		{
			sned_to_datagather(timestamp_start, timestamp_end); // datagather로 전송
			free(timestamp_start);
			free(timestamp_end);
		}
	}
	close(server);	   // 서버 소켓 닫기
	SSL_CTX_free(ctx); // SSL context 해제

	return (void *)4;
}

int main(int argc, char **argv)
{
	pthread_t threads[4];
	void *(*jobs[4])(void *data);
	jobs[0] = t_ps;
	jobs[1] = t_shm;
	jobs[2] = t_filewrite;
	jobs[3] = t_ssl;
	int thread_input[4] = {1, 1, 1, 1};
	char *thread_ret[4];

	for (int i = 0; i < 4; i++)
	{
		thread_input[i] = i + 1;
		if (pthread_create(&threads[i], NULL, *jobs[i], (void *)&thread_input[i]) < 0)
		{
			perror("thread create error:");
			return -1;
		}
	}

	// sleep(TIMETORUN);	//실행시간 지정
	// for (int i = 0; i < 4; i++)
	//	thread_input[i] = 0; //스레드 loop 종료 조건 지정

	for (int i = 0; i < 4; i++)
	{
		pthread_join(threads[i], (void *)&thread_ret[i]);			  // 반환값 저장
		fprintf(stderr, "Thread %d End with %d\n", i, thread_ret[i]); // 스레드 반환값 출력
	}
	return 0;
}
