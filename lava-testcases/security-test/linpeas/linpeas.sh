#!/bin/bash

set -x


OUTPUT="$(pwd)/output"
mkdir -p "$OUTPUT"
RESULT_FILE="${OUTPUT}/result.txt"
OUTPUT_FILE="/tmp/linpeas_output.txt"
JSON_FILE="/tmp/linpeas_output.json"

TEST_USER="lava_test"
LINPEAS_SCRIPT="/tmp/linpeas.sh"

# Ensure cleanup on exit
cleanup() {
    if id "$TEST_USER" &>/dev/null; then
      userdel -r "$TEST_USER" 2>/dev/null || true
      rm -f "$LINPEAS_SCRIPT" "$OUTPUT_FILE"
    fi
}
trap cleanup EXIT

#处理数据
# ========== 公共 jq 函数定义 ==========
JQ_COMMON_FUNCS='
  def level_map($color):
    if $color == "REDYELLOW" then "2"
    elif $color == "RED" then "1"
    else ""
    end;

  def format_output($section; $name; $desc; $result; $color):
    {
      section: $section,
      name: $name,
      description: $desc,
      result: $result,
      color: $color,
      level: level_map($color)
    };
'

# -----------------------------
# 1. 检测内核漏洞
# -----------------------------
check_kernel_vulns() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
[
  .["System Information"].sections
  | to_entries[]
  | select(.key | contains("CVE"))
  | .key as $section_name
  | .value.lines[]
  | select(.colors | keys | any(. == "RED" or . == "REDYELLOW"))
  | {
      text: .clean_text,
      colors: (.colors | keys | join(", ")),
      cve_id: (
        (.clean_text | capture("(?<cve>CVE-[0-9]{4}-[0-9]+)").cve)
        // ($section_name | capture("(?<cve>CVE-[0-9]{4}-[0-9]+)").cve)
        // null
      )
    }
 ] as $cve_results

 | if ($cve_results | length) > 0 then
    $cve_results
    | group_by(.cve_id)[]
    | .[0]
    | format_output("kernel_vulns_check"; .cve_id; .text; "fail"; .colors)
  else
      format_output("kernel_vulns_check"; "kernel_vulns_check"; "kernel_vulns_check have no high-risk"; "pass"; "")
  end
 | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
 | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# -----------------------------
# 2. 提取高危内核配置
# -----------------------------
check_kernel_config() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'

  def extract($path; $node):
    (($node.lines // [])[] | select(
      (.clean_text | test("disabled|0\\s*$|Not Found|Not set|not set |Not enforced|can be loaded"; "i")) and
      (.colors | keys | map(select(. == "RED" or . == "REDYELLOW")) | length > 0)
    ) | {
      section: $path,
      text: .clean_text,
      colors: (.colors | keys | map(select(. == "RED" or . == "REDYELLOW")) | join(", "))
    }),
    (($node.sections // {}) | to_entries[] | extract($path + "/" + .key; .value));

  def kernel_name_map($section; $text):
    if ($section | test("Seccomp"; "i")) then "kernel_Seccomp_enable"
    elif ($section | test("ptrace"; "i")) then "kernel_ptrace_scope"
    elif ($section | test("kptr_restrict"; "i")) then "kernel_kptr_restrict"
    elif ($section | test("unpriv_bpf"; "i")) then "kernel_unpriv_bpf_disabled"
    elif ($section | test("modules loadable"; "i")) then "kernel_modules_loadable"
    elif ($section | test("signature enforcement"; "i")) then "kernel_module_signature"
    elif ($text | test("Seccomp"; "i")) then "kernel_Seccomp_enable"
    elif ($text | test("ptrace"; "i")) then "kernel_ptrace_scope"
    elif ($text | test("kptr_restrict"; "i")) then "kernel_kptr_restrict"
    elif ($text | test("unpriv_bpf"; "i")) then "kernel_unpriv_bpf_disabled"
    elif ($text | test("modules can be loaded"; "i")) then "kernel_modules_loadable"
    elif ($text | test("not enforced"; "i")) then "kernel_module_signature"
    else ($section | split("/") | last | gsub("\\s+"; "_") | ascii_downcase)
    end;

  [
    .["System Information"].sections // {} | to_entries[] | extract(.key; .value)
  ] as $kernel_results

  | if ($kernel_results | length) > 0 then
      $kernel_results
      | group_by(.section + "|" + .text)[]
      | .[0]
      | format_output(
          "kernel_config_check";
          kernel_name_map(.section; .text);
          .text;
          "fail";
          .colors
        )
    else
      format_output("kernel_config_check"; "kernel_config_check"; "kernel_config_check have no high-risk"; "pass"; "")
    end
  | {name, result, level, color}
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 3. 检测 SUID/SGID 权限
# ---------------------------
check_suid_sgid() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  def extract($path; $node):
    (($node.lines // [])[] | select(
      (.clean_text | test("suid|sgid|SUID|SGID|rws|rwx--s--x|r-xr-sr-x|---s--x--x|---s--x|---s"; "i")) and
      (.colors | keys | map(select(. == "RED" or . == "REDYELLOW")) | length > 0)
    ) | {
      section: $path,
      text: .clean_text,
      colors: (.colors | keys | map(select(. == "RED" or . == "REDYELLOW")) | join(", "))
    }),
    (($node.sections // {}) | to_entries[] | extract($path + "/" + .key; .value));

  def simplify_name($text):
    if $text | test("sudo"; "i") then "sudo_privesc"
    elif $text | test("mount"; "i") then "mount_privesc"
    elif $text | test("umount"; "i") then "umount_privesc"
    elif $text | test("newgrp"; "i") then "newgrp_privesc"
    elif $text | test("passwd"; "i") then "passwd_privesc"
    elif $text | test("write"; "i") then "write_privesc"
    elif $text | test("wall"; "i") then "wall_privesc"
    elif $text | test("utempter"; "i") then "utempter_privesc"
    elif $text | test("ssh-keysign"; "i") then "ssh_keysign_privesc"
    elif $text | test("SUID"; "i") then "suid_risk"
    elif $text | test("SGID"; "i") then "sgid_risk"
    else "suid_sgid_risk"
    end;

  [
    .["Files with Interesting Permissions"].sections // {} | to_entries[] | extract(.key; .value)
  ] as $perm_results

  | if ($perm_results | length) > 0 then
      $perm_results
      | group_by(.section + "|" + .text)[]
      | .[0]
      | format_output("suid_sgid_check"; simplify_name(.text); .text; "fail"; .colors)
    else
      format_output("suid_sgid_check"; "suid_sgid_check"; "suid_sgid_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE"  >> $RESULT_FILE
}

# ---------------------------
# 4. 检测 Capabilities
# ---------------------------
check_capabilities() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  .["Files with Interesting Permissions"].sections["Capabilities (T1548.001)"].sections["Processes with capability sets (non-zero CapEff/CapAmb, limit 40) (T1548.001)"].lines as $lines

  | [
      range(0; $lines | length) as $i
      | $lines[$i]
      | select(.clean_text | startswith("PID"))
      | {
          pid_line: .clean_text,
          user: ((.clean_text | split("user=")[1] // "unknown") | split(" ")[0]),
          cap_eff_text: ($lines[$i+3].clean_text // ""),
          cap_eff_colors: ($lines[$i+3].colors // {})
        }
      | select(
          .user != "root" and
          (.cap_eff_text | test("CapEff:")) and
          (.cap_eff_text | test("0x0{16}=") | not) and
          (.cap_eff_colors | keys | map(select(. == "RED" or . == "REDYELLOW")) | length > 0)
        )
    ] as $risk_caps

  | if ($risk_caps | length) > 0 then
      $risk_caps[]
      | format_output("capabilities_check";
          ("nonroot_cap_" + .user + "_" + (.pid_line | capture("PID\\s+(?<p>\\d+)").p));
          (.pid_line + " | " + .cap_eff_text[0:70]);
          "fail";
          "RED")
    else
      format_output("capabilities_check"; "capabilities_check"; "capabilities_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 5. 检测 Unix Sockets 权限
# ---------------------------
check_unix_sockets() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  .["Processes, Crons, Timers, Services and Sockets"].sections["Unix Sockets Analysis (T1571,T1049)"].lines as $lines

  | [
      range(0; $lines | length) as $i
      | $lines[$i]
      | select(.clean_text | startswith("/"))
      | {
          path: .clean_text,
          # 获取后续几行直到下一个路径或空行
          perms: ($lines[$i+1].clean_text // ""),
          owner: ($lines[$i+2].clean_text // ""),
          risk: ($lines[$i+3].clean_text // ""),
          has_high_risk: (
            ($lines[$i+3].colors // {}) | keys | map(select(. == "REDYELLOW")) | length > 0
          ),
          is_777: ($lines[$i+1].clean_text | test("777"))
        }
      | select(.has_high_risk or .is_777)
    ] as $risk_sockets

  | if ($risk_sockets | length) > 0 then
      $risk_sockets[]
      | {
          name: (.path | gsub("/"; "_") | gsub("^_"; "")),
          desc: (.path + " | " + .perms + " | " + .owner + " | " + .risk),
          color: (if .is_777 then "RED" else "REDYELLOW" end)
        } as $info
      | format_output("unix_sockets_check"; $info.name; $info.desc; "fail"; $info.color)
    else
      format_output("unix_sockets_check"; "unix_sockets_check"; "unix_sockets_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 6. 检测 SSH 配置
# ---------------------------
check_ssh_config() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  [
    .["Software Information"].sections["Analyzing SSH Files (limit 70)"].sections["Some certificates were found (out limited): (T1552.004,T1021.004)"].lines[]
    | select(.colors | keys | any(. == "RED" or . == "REDYELLOW"))
    | {
        text: .clean_text,
        colors: (.colors | keys | join(", "))
      }
  ] as $ssh_results

  | if ($ssh_results | length) > 0 then
      $ssh_results[]
      | format_output("ssh_config_check"; (.text | split(" ") | first); .text; "fail"; .colors)
    else
      format_output("ssh_config_check"; "ssh_config_check"; "ssh_config_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 7. 检测 PAM 配置
# ---------------------------
check_pam_config() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  [
    .["Software Information"].sections["Analyzing PAM Auth Files (limit 70)"].lines[]
    | .clean_text
  ] as $all_lines

  | reduce $all_lines[] as $line (
      {current_file: null, files: {}};

      if ($line | contains("/etc/pam.d/")) and ($line | test("^[d-][rwx-]{9}[.]")) then
        (
          .current_file = ($line | split("/etc/pam.d/") | last | split(" ") | first)
          | if ($line | contains(" -> ")) then .current_file = null else . end
          | if .current_file != null then
              .files[.current_file] = {configs: [], risks: []}
            else
              .
            end
        )

      elif ($line | test("^[d-][rwx-]{9}[.]")) then
        .

      elif ($line | test("^(auth|account|password|session)[[:space:]]+(required|requisite|sufficient|optional|include|substack)")) then
        if .current_file != null then
          (
            .files[.current_file].configs += [$line]
            | if ($line | contains("nullok")) then
                .files[.current_file].risks += ["nullok"]
              elif ($line | contains("pam_permit.so")) then
                .files[.current_file].risks += ["pam_permit"]
              elif ($line | contains("pam_rootok.so")) then
                .current_file as $cf
                | if ($cf == "su" or $cf == "su-local" or $cf == "su-l" or $cf == "su-bak" or
                      $cf == "runuser" or $cf == "runuser-l") then
                    .
                  else
                    .files[$cf].risks += ["pam_rootok"]
                  end
              else
                .
              end
          )
        else
          .
        end

      else
        .
      end
    )
  | .files as $file_data

  | $file_data
  | to_entries
  | map(select(.value.risks | length > 0))
  | if length > 0 then
      .[]
      | .key as $filename
      | .value as $file_info
      | $file_info.risks as $risk_types
      | $file_info.configs as $all_configs

      | [
          "=== File: /etc/pam.d/" + $filename + " ===",
          "=== Risks: " + ($risk_types | join(", ")) + " ===",
          ($all_configs | map(
            if . | contains("nullok") then "  [!] nullok: " + .
            elif . | contains("pam_permit.so") then "  [!] pam_permit: " + .
            elif . | contains("pam_rootok.so") then
              if ($filename == "su" or $filename == "su-local" or $filename == "su-l" or $filename == "su-bak" or
                  $filename == "runuser" or $filename == "runuser-l") then
                "  [ ] pam_rootok (expected): " + .
              else
                "  [!] pam_rootok: " + .
              end
            else "  [ ] " + .
            end
          ) | join("\n"))
        ] as $desc_lines

      | format_output(
          "pam_config_check";
          ($filename + " (" + ($risk_types | unique | join(", ")) + ")");
          ($desc_lines | join("\n"));
          "fail";
          "RED"
        )
    else
      format_output("pam_config_check"; "pam_config_check"; "pam_config_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 8. 检测网络端口
# ---------------------------
check_network_ports() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  # 标准/低风险端口白名单
  def is_safe_port($port):
    $port == "22" or    # SSH
    $port == "80" or    # HTTP
    $port == "443" or   # HTTPS
    $port == "53" or    # DNS
    $port == "123" or   # NTP
    $port == "25" or    # SMTP (如需要)
    $port == "587" or   # SMTP TLS
    $port == "143" or   # IMAP
    $port == "993" or   # IMAPS
    $port == "110" or   # POP3
    $port == "995";     # POP3S

  # 高风险端口黑名单（无论是否标红，直接告警）
  def is_high_risk_port($port):
    $port == "23" or     # Telnet - 明文，无加密
    $port == "21" or    # FTP - 明文传输
    $port == "69" or    # TFTP - 无认证
    $port == "111" or   # RPCbind - 常被利用
    $port == "135" or   # MS RPC
    $port == "139" or   # NetBIOS
    $port == "445" or   # SMB
    $port == "2049" or  # NFS
    $port == "3306" or  # MySQL - 不应暴露公网
    $port == "5432" or  # PostgreSQL
    $port == "6379" or  # Redis - 无认证常被入侵
    $port == "27017" or # MongoDB
    $port == "9200" or  # Elasticsearch
    $port == "8080" or  # 常见管理后台/代理
    $port == "8443" or  # 常见管理后台
    $port == "8888" or  # Jupyter 等
    $port == "3000" or  # 开发端口
    $port == "5000" or  # Flask 等开发端口
    $port == "5900" or  # VNC
    $port == "6000" or  # X11
    $port == "3389";    # RDP

  [
    .["Network Information"].sections["Active Ports (T1049)"].sections["Active Ports (netstat) (T1049)"].lines[]
    | .clean_text
    | capture("^\\s*(?<proto>tcp6?)\\s+\\d+\\s+\\d+\\s+(?<local>[0-9a-fA-F:.]+):(?<port>\\d+)\\s+(?<remote>[0-9a-fA-F:.]+:[*])\\s+(?<state>\\w+)")
    | . + {risk: "unknown"}
    | if (.port | is_safe_port(.)) then .risk = "safe"
      elif (.port | is_high_risk_port(.)) then .risk = "high"
      else .risk = "nonstandard"
      end
  ] as $parsed_ports

  # 只输出非安全端口
  | $parsed_ports
  | map(select(.risk != "safe"))
  | if length > 0 then
      .[]
      | format_output(
          "network_ports_check";
          .port;
          (.proto + " " + .local + ":" + .port + " -> " + .remote + " [" + .state + "]" +
           if .risk == "high" then " [HIGH RISK PORT]" else " [NONSTANDARD PORT]" end);
          "fail";
          (if .risk == "high" then "RED" else "YELLOW" end)
        )
    else
      format_output("network_ports_check"; "network_ports_check"; "network_ports_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 9. 检测防火墙状态
# ---------------------------
check_firewall_status() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  [
    .["Network Information"].sections["Firewall Rules Analysis (T1016)"].sections[]
    | .lines[]
    | select(.colors | keys | any(. == "RED" or . == "REDYELLOW"))
    | {
        text: .clean_text,
        colors: (.colors | keys | join(", "))
      }
  ] as $fw_results

  | if ($fw_results | length) > 0 then
      $fw_results[]
      | format_output("firewall_check"; (.text | split(" ") | first); .text; "fail"; .colors)
    else
      format_output("firewall_check"; "firewall_check"; "firewall_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 10. 检测容器状态
# ---------------------------
check_container_status() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  [
    .["Container"].sections["Container details (T1613,T1611)"].lines[]
    | select(.colors | keys | any(. == "RED" or . == "REDYELLOW"))
    | {
        text: .clean_text,
        colors: (.colors | keys | join(", "))
      }
  ] as $container_results

  | if ($container_results | length) > 0 then
      $container_results[]
      | format_output("container_check"; (.text | split(" ") | first); .text; "fail"; .colors)
    else
      format_output("container_check"; "container_check"; "container_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 11. 检测用户权限
# ---------------------------
check_user_privs() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  [
    .["Users Information"].sections["Checking Pkexec and Polkit (T1548.003,T1548.004,T1068)"].lines[]
    | select(.colors | keys | any(. == "RED" or . == "REDYELLOW"))
    | {
        text: .clean_text,
        colors: (.colors | keys | join(", "))
      }
  ] as $user_results

  | if ($user_results | length) > 0 then
      $user_results[]
      | format_output("user_privs_check"; (.text | split(" ") | first); .text; "fail"; .colors)
    else
      format_output("user_privs_check"; "user_privs_check"; "user_privs_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}

# ---------------------------
# 12. 检测 Sudo 配置
# ---------------------------
function check_sudo_config() {
  local JSON_FILE="$1"
  jq -r "$JQ_COMMON_FUNCS"'
  [
    .["Users Information"].sections["Checking sudo tokens (T1548.003)"].lines[]
    | select(.colors | keys | any(. == "RED" or . == "REDYELLOW"))
    | {
        text: .clean_text,
        colors: (.colors | keys | join(", "))
      }
  ] as $sudo_results

  | if ($sudo_results | length) > 0 then
      $sudo_results[]
      | format_output("sudo_check"; (.text | split(" ") | first); .text; "fail"; .colors)
    else
      format_output("sudo_check"; "sudo_check"; "sudo_check have no high-risk"; "pass"; "")
    end
  | [.name, (.result // ""), (.level // ""), (.color // ""), (.section // ""), (.description // "")]
  | join(" ")
' "$JSON_FILE" >> $RESULT_FILE
}


#执行linpeas
# 1.创建非root测试用户
echo "Creating test user: $TEST_USER"
useradd -m -s /bin/bash "$TEST_USER"

# 2.下载LinPEAS执行脚本
if [ ! -f "$LINPEAS_SCRIPT" ]; then
    echo "Downloading LinPEAS..."
    # 强制清除所有可能的代理设置
    unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY
    export http_proxy=''
    export https_proxy=''
    export all_proxy=''
    env | grep -i proxy || echo 'Proxy cleared'
    # 下载
    curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o "$LINPEAS_SCRIPT"
    chmod +x "$LINPEAS_SCRIPT"
    chown "$TEST_USER:$TEST_USER" "$LINPEAS_SCRIPT"
fi

# 3.非root用户运行LinPEAS
echo "Running LinPEAS as user '$TEST_USER'..."
su - "$TEST_USER" -c "$LINPEAS_SCRIPT -a"  > "$OUTPUT_FILE" 2>&1
# 4.解析LinPEAS运行结果为json格式,检查是否有越权风险并转化为lava格式
dnf install -y jq git
git clone https://github.com/peass-ng/PEASS-ng.git
python3 ./PEASS-ng/parsers/peas2json.py $OUTPUT_FILE $JSON_FILE
chmod 644 "$JSON_FILE"
check_kernel_vulns "$JSON_FILE"
check_kernel_config "$JSON_FILE"
check_suid_sgid "$JSON_FILE"
check_capabilities "$JSON_FILE"
check_unix_sockets "$JSON_FILE"
check_ssh_config "$JSON_FILE"
check_pam_config "$JSON_FILE"
check_network_ports "$JSON_FILE"
check_firewall_status "$JSON_FILE"
check_container_status "$JSON_FILE"
check_user_privs "$JSON_FILE"
check_sudo_config "$JSON_FILE"
sleep 1800