#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from mininet.net import Mininet
from mininet.node import Host, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import time

# FRR配置和日志目录
FRR_BASE_DIR = '/tmp/frr_experiment' 
FRR_CONF_DIR = os.path.join(FRR_BASE_DIR, 'configs')
FRR_LOG_DIR = os.path.join(FRR_BASE_DIR, 'logs')
FRR_RUN_DIR = os.path.join(FRR_BASE_DIR, 'run') 

def ensure_clean_directories():
    """确保FRR相关目录是干净的"""
    info(f"*** 正在清理旧的FRR实验目录: {FRR_BASE_DIR}\n")
    if os.path.exists(FRR_BASE_DIR):
        os.system(f"sudo rm -rf {FRR_BASE_DIR}")
    
    for dir_path in [FRR_CONF_DIR, FRR_LOG_DIR, FRR_RUN_DIR]:
        os.makedirs(dir_path, exist_ok=True)
        info(f"*** 已创建目录: {dir_path}\n")
    os.system(f"sudo chmod -R 777 {FRR_BASE_DIR}")


def create_router_conf(router_name, interfaces):
    """为路由器创建FRR配置文件"""
    conf_file_path = os.path.join(FRR_CONF_DIR, f"{router_name}.conf")
    log_file_path = os.path.join(FRR_LOG_DIR, f'{router_name}.log')
    
    config_content = f"""\
hostname {router_name}
password zebra
enable password zebra
log syslog informational
log file {log_file_path} informational
!
debug rip events
debug rip packet
debug zebra events
debug zebra packet detail
!
"""
    for if_name, if_data in interfaces.items():
        config_content += f"""\
interface {if_name}
 ip address {if_data['ip']}
 no shutdown
!
"""
    config_content += """\
router rip
 version 2
"""
    for if_name, if_data in interfaces.items():
        config_content += f" network {if_data['network']}\n"
    
    config_content += """\
exit
!
line vty
 no login
!
end
"""
    with open(conf_file_path, 'w') as f:
        f.write(config_content)
    
    info(f"--- {router_name} 的 FRR 配置文件 ({conf_file_path}) 内容如下: ---\n")
    try:
        with open(conf_file_path, 'r') as f_read:
            info(f_read.read())
    except Exception as e:
        info(f"无法读取配置文件 {conf_file_path}: {e}\n")
    info(f"--- {router_name} 的 FRR 配置文件内容结束 ---\n")
    
    return conf_file_path

def start_frr_daemons(host, conf_file_path):
    """在主机上启动zebra和ripd守护进程"""
    if not os.path.exists(conf_file_path):
        info(f"!!! 错误: 找不到 {host.name} 的FRR配置文件 {conf_file_path}\n")
        return

    frr_sbin_paths = ["/usr/lib/frr", "/usr/local/sbin", "/usr/sbin"]
    frr_path = None
    for path_prefix in frr_sbin_paths:
        if os.path.exists(os.path.join(path_prefix, "zebra")):
            frr_path = path_prefix
            break
    
    if not frr_path:
        info(f"!!! 错误: 在{frr_sbin_paths}中找不到FRR执行文件。请检查FRR安装路径。\n")
        return

    zebra_cmd_path = os.path.join(frr_path, "zebra")
    ripd_cmd_path = os.path.join(frr_path, "ripd")

    zebra_pid = os.path.join(FRR_RUN_DIR, f"{host.name}-zebra.pid")
    zebra_sock = os.path.join(FRR_RUN_DIR, f"{host.name}-zebra.sock") 
    ripd_pid = os.path.join(FRR_RUN_DIR, f"{host.name}-ripd.pid")

    host.cmd(f"test -f {zebra_pid} && sudo kill $(cat {zebra_pid} 2>/dev/null) > /dev/null 2>&1 || true")
    host.cmd(f"test -f {ripd_pid} && sudo kill $(cat {ripd_pid} 2>/dev/null) > /dev/null 2>&1 || true")
    time.sleep(0.5)
    host.cmd(f"sudo rm -f {zebra_pid} {zebra_sock} {ripd_pid}")

    zebra_options = f"-d -f {conf_file_path} -z {zebra_sock} -i {zebra_pid} -A 127.0.0.1"
    ripd_options = f"-d -f {conf_file_path} -z {zebra_sock} -i {ripd_pid} -A 127.0.0.1"

    info(f"*** 正在为 {host.name} 启动 zebra: {zebra_cmd_path} {zebra_options}\n")
    host.cmd(f"{zebra_cmd_path} {zebra_options} >> {os.path.join(FRR_LOG_DIR, f'{host.name}-zebra-stdout.log')} 2>&1 &")
    time.sleep(2.5) 

    ps_zebra_output = host.cmd(f"ps aux | grep '{zebra_cmd_path}.*{host.name}-zebra.pid' | grep -v grep")
    if f"{host.name}-zebra.pid" in ps_zebra_output:
        info(f"*** Zebra 进程看起来已在 {host.name} 上启动。\n")
    else:
        info(f"!!! Zebra 进程可能未能在 {host.name} 上成功启动。输出: '{ps_zebra_output}'. 请检查日志。\n")

    info(f"*** 正在为 {host.name} 启动 ripd: {ripd_cmd_path} {ripd_options}\n")
    host.cmd(f"{ripd_cmd_path} {ripd_options} >> {os.path.join(FRR_LOG_DIR, f'{host.name}-ripd-stdout.log')} 2>&1 &")
    time.sleep(1.5)

    ps_ripd_output = host.cmd(f"ps aux | grep '{ripd_cmd_path}.*{host.name}-ripd.pid' | grep -v grep")
    if f"{host.name}-ripd.pid" in ps_ripd_output:
        info(f"*** RIPd 进程看起来已在 {host.name} 上启动。\n")
    else:
        info(f"!!! RIPd 进程可能未能在 {host.name} 上成功启动。输出: '{ps_ripd_output}'. 请检查日志。\n")

    info(f"*** 已尝试在 {host.name} 上启动FRR守护进程。\n")


def stop_frr_daemons(host):
    """停止主机上的FRR守护进程"""
    zebra_pid_file = os.path.join(FRR_RUN_DIR, f"{host.name}-zebra.pid")
    ripd_pid_file = os.path.join(FRR_RUN_DIR, f"{host.name}-ripd.pid")
    
    host.cmd(f"test -f {zebra_pid_file} && sudo kill $(cat {zebra_pid_file} 2>/dev/null) > /dev/null 2>&1 || true")
    host.cmd(f"test -f {ripd_pid_file} && sudo kill $(cat {ripd_pid_file} 2>/dev/null) > /dev/null 2>&1 || true")
    time.sleep(0.5)
    host.cmd("sudo killall -q zebra ripd || true") 
    host.cmd(f"sudo rm -f {zebra_pid_file} {os.path.join(FRR_RUN_DIR, f'{host.name}-zebra.sock')} {ripd_pid_file}")
    info(f"*** 已尝试停止 {host.name} 上的FRR守护进程并清理相关文件\n")


def run_network():
    info("*** 正在清理旧的Mininet实例 (sudo mn -c)\n")
    os.system("sudo mn -c > /dev/null 2>&1")
    
    ensure_clean_directories()

    net = Mininet(controller=None, link=TCLink, switch=OVSKernelSwitch)

    info('*** 正在添加路由器节点\n')
    r1 = net.addHost('r1', ip=None)
    r2 = net.addHost('r2', ip=None)
    r3 = net.addHost('r3', ip=None)
    r4 = net.addHost('r4', ip=None)
    r5 = net.addHost('r5', ip=None)
    routers = [r1, r2, r3, r4, r5]

    info('*** 正在添加链路\n')
    net.addLink(r1, r2, intfName1='r1-eth0', intfName2='r2-eth0')
    net.addLink(r2, r3, intfName1='r2-eth1', intfName2='r3-eth0')
    net.addLink(r1, r4, intfName1='r1-eth1', intfName2='r4-eth0')
    net.addLink(r2, r5, intfName1='r2-eth2', intfName2='r5-eth0')
    net.addLink(r3, r5, intfName1='r3-eth1', intfName2='r5-eth1')
    net.addLink(r4, r5, intfName1='r4-eth1', intfName2='r5-eth2')

    info('*** 正在启动网络...\n')
    net.build()

    info('*** 正在各路由器上配置FRR...\n')
    # IP地址定义
    r1_interfaces = {
        'r1-eth0': {'ip': '10.0.1.1/24', 'network': '10.0.1.0/24'},
        'r1-eth1': {'ip': '10.0.2.1/24', 'network': '10.0.2.0/24'}
    }
    r2_interfaces = {
        'r2-eth0': {'ip': '10.0.1.2/24', 'network': '10.0.1.0/24'},
        'r2-eth1': {'ip': '10.0.3.1/24', 'network': '10.0.3.0/24'},
        'r2-eth2': {'ip': '10.0.4.1/24', 'network': '10.0.4.0/24'}
    }
    r3_interfaces = {
        'r3-eth0': {'ip': '10.0.3.2/24', 'network': '10.0.3.0/24'},
        'r3-eth1': {'ip': '10.0.5.1/24', 'network': '10.0.5.0/24'}
    }
    r4_interfaces = {
        'r4-eth0': {'ip': '10.0.2.2/24', 'network': '10.0.2.0/24'},
        'r4-eth1': {'ip': '10.0.6.1/24', 'network': '10.0.6.0/24'}
    }
    r5_interfaces = {
        'r5-eth0': {'ip': '10.0.4.2/24', 'network': '10.0.4.0/24'},
        'r5-eth1': {'ip': '10.0.5.2/24', 'network': '10.0.5.0/24'},
        'r5-eth2': {'ip': '10.0.6.2/24', 'network': '10.0.6.0/24'}
    }
    router_configs_map = {
        r1: r1_interfaces, r2: r2_interfaces, r3: r3_interfaces,
        r4: r4_interfaces, r5: r5_interfaces
    }

    for router_node, interfaces_data in router_configs_map.items():
        info(f"--- 正在配置路由器: {router_node.name} ---\n")
        for if_name in interfaces_data.keys():
            router_node.cmd(f"sysctl net.ipv6.conf.{if_name}.disable_ipv6=1 > /dev/null 2>&1")
        
        conf_file = create_router_conf(router_node.name, interfaces_data)
        start_frr_daemons(router_node, conf_file)
        
        info(f"--- {router_node.name} 启动FRR后的内核IP地址 (ip addr show): ---\n")
        kernel_ips = router_node.cmd('ip addr show')
        info(kernel_ips + "\n")
        info(f"--- {router_node.name} 的内核IP地址信息结束 ---\n")
        time.sleep(0.5)

    info("\n*** 网络配置完成。等待RIP协议收敛 (大约 30-60 秒)...\n")
    info("**************************************************************************************\n")
    info("*** 重要提示：请仔细检查上方控制台输出中生成的 frr.conf 文件内容、进程检查结果和内核IP地址。***\n")
    info(f"*** 同时，请务必检查FRR日志：主日志在 {FRR_LOG_DIR}/<router_name>.log, stdout/stderr 重定向日志在 {FRR_LOG_DIR}/<router_name>-<daemon>-stdout.log ***\n")
    info("**************************************************************************************\n")
    time.sleep(45)

    # 实验步骤循环
    # 定义一个包含每个步骤的函数或lambda的列表，方便管理
    experiment_steps = [
        {"name": "步骤1: 初始路由表 (收敛后)", "action": lambda: None, "wait_after_action": 0},
        {"name": "步骤2: 测试初始连通性", 
         "action": lambda: test_connectivity(r1, '10.0.5.1', '10.0.6.2'), 
         "wait_after_action": 0, "is_connectivity_test": True},
        {"name": "步骤3: R2-R5 链路断开后的路由表", 
         "action": lambda: net.configLinkStatus('r2', 'r5', 'down'), 
         "wait_after_action": 70, "link_change_message": "\n正在断开 r2 和 r5 之间的链路...\n链路 R2-R5 已断开。等待RIP重新收敛..."},
        {"name": "步骤4: R2-R5 链路恢复后的路由表", 
         "action": lambda: net.configLinkStatus('r2', 'r5', 'up'), 
         "wait_after_action": 45, "link_change_message": "\n正在重新连接 r2 和 r5 之间的链路...\n链路 R2-R5 已恢复。等待RIP重新收敛..."}
    ]

    for step_config in experiment_steps:
        step_name = step_config["name"]
        info("\n" + "*" * 40)
        info(f"*** {step_name} ***")
        info("*" * 40)

        if "link_change_message" in step_config:
            info(step_config["link_change_message"] + "\n")
        
        step_config["action"]() # 执行动作，如断开/连接链路或无操作

        if step_config["wait_after_action"] > 0:
            time.sleep(step_config["wait_after_action"])

        if not step_config.get("is_connectivity_test", False): # 如果不是连通性测试步骤，则显示路由表
            for router_node in routers:
                info(f"\n--- {router_node.name} 的 RIP 路由表 ({step_name}) ---\n")
                # 让vtysh自动发现socket
                output_rip = router_node.cmd(f'vtysh -c "show ip rip"')
                if "Exiting: failed to connect" in output_rip or \
                   "Connection refused" in output_rip or \
                   "Can't connect to" in output_rip or \
                   "invalid option -- " in output_rip:
                    info(f"无法获取 {router_node.name} 的 'show ip rip' 输出。Vtysh输出: {output_rip}")
                    info(f"请检查FRR日志: {FRR_LOG_DIR}/{router_node.name}.log 和 {FRR_LOG_DIR}/{router_node.name}-*-stdout.log")
                    info(f"提示: 您可以在 Mininet CLI 中手动尝试 'rX vtysh -c \"show ip rip\"' (将 rX 替换为实际路由器名)")
                else:
                    info(output_rip)

                info(f"\n--- {router_node.name} 的内核路由表 (ip route) ({step_name}) ---\n")
                kernel_route = router_node.cmd('ip route')
                info(kernel_route)
                input(f"已暂停: 请截图或记录 {router_node.name} 的路由表 ({step_name})。按回车键继续...")

    info('*** 实验步骤执行完毕。输入 "quit" 退出 Mininet CLI。\n')
    CLI(net)

    info('*** 正在停止网络...\n')
    for router_node_stop in routers: 
        stop_frr_daemons(router_node_stop)
    net.stop()
    info('*** 实验脚本运行结束 ***')

def test_connectivity(source_router, r3_target_ip, r5_target_ip):
    """执行连通性测试"""
    info(f"\n--- 从 {source_router.name} ping R3 的接口 {r3_target_ip} ---")
    result_r1_r3 = source_router.cmd(f'ping -c 3 {r3_target_ip}')
    info(result_r1_r3)
    input(f"已暂停: 请记录 {source_router.name} ping R3 ({r3_target_ip}) 的结果。按回车键继续...")

    info(f"\n--- 从 {source_router.name} ping R5 的接口 {r5_target_ip} ---")
    result_r1_r5 = source_router.cmd(f'ping -c 3 {r5_target_ip}')
    info(result_r1_r5)
    input(f"已暂停: 请记录 {source_router.name} ping R5 ({r5_target_ip}) 的结果。按回车键继续...")


if __name__ == '__main__':
    setLogLevel('info')
    run_network()