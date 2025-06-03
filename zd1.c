#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1;
    }
    return 0;
}

int check_selinux() {
    return file_exists("/sys/fs/selinux/enforce");
}

int check_apparmor() {
    return file_exists("/sys/module/apparmor/parameters/enabled");
}

int check_aslr() {
    FILE *f = fopen("/proc/sys/kernel/randomize_va_space", "r");
    if (!f) return 0;
    int val = 0;
    fscanf(f, "%d", &val);
    fclose(f);
    return val == 2;
}

int check_stack_canary() {
    FILE *f = popen("readelf -s /bin/ls 2>/dev/null | grep '__stack_chk_fail'", "r");
    if (!f) return 0;
    char buf[256];
    int found = fgets(buf, sizeof(buf), f) != NULL;
    pclose(f);
    return found;
}

int check_proc_mount_options() {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;
    char line[512];
    int secure = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "/proc") || strstr(line, "/sys")) {
            if (strstr(line, "noexec") || strstr(line, "nosuid") || strstr(line, "nodev"))
                secure++;
        }
    }
    fclose(f);
    return secure > 0;
}

int check_root_login() {
    FILE *f = fopen("/etc/ssh/sshd_config", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "PermitRootLogin no")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

int main() {
    int score = 0;

    if (check_selinux()) {
        printf("[+] SELinux увімкнено\n");
        score++;
    } else if (check_apparmor()) {
        printf("[+] AppArmor увімкнено\n");
        score++;
    } else {
        printf("[-] SELinux / AppArmor не увімкнено\n");
    }

    if (check_aslr()) {
        printf("[+] ASLR увімкнено\n");
        score++;
    } else {
        printf("[-] ASLR вимкнено\n");
    }

    if (check_stack_canary()) {
        printf("[+] Stack Canary присутній\n");
        score++;
    } else {
        printf("[-] Stack Canary відсутній\n");
    }

    if (check_proc_mount_options()) {
        printf("[+] /proc або /sys мають захищені опції монтування\n");
        score++;
    } else {
        printf("[-] /proc або /sys без захисту\n");
    }

    if (check_root_login()) {
        printf("[+] Root login через SSH заборонено\n");
        score++;
    } else {
        printf("[-] Root login через SSH дозволено\n");
    }

    printf("\nЗагальний рівень параноїдальності: %d/5\n", score);

    if (score == 5)
        printf("Найбільш параноїдальна конфігурація!\n");
    else if (score >= 3)
        printf("Середній рівень захисту\n");
    else
        printf("Низький рівень безпеки. Рекомендується переглянути налаштування.\n");

    return 0;
}
