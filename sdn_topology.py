#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
스마트네트워크서비스 - SDN 실습용 토폴로지 (학생용 버전)

구성:
 - 스위치 3개 (s1 - s2 - s3)
 - 호스트 4개 (h1, h2, h3, h4)
 - 외부 Ryu 컨트롤러 연결

TODO(보고서용):
1) 이 토폴로지 구조를 직접 그림으로 그려오기
2) 각 호스트/스위치의 역할을 정리해오기
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI


def create_topology():
    net = Mininet(
        controller=RemoteController,
        link=TCLink,
        switch=OVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True
    )

    info('*** Adding controller\n')
    # TODO: 필요하면 컨트롤러 IP/포트를 변경해보고,
    #       왜 변경했는지 보고서에 설명하기
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')

    info('*** Adding hosts\n')
    # TODO: 아래 IP들이 같은 서브넷(10.0.0.0/24)에 속하는지 확인해보기
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')

    info('*** Creating links\n')

    # Host - Switch
    net.addLink(h1, s1, bw=100)
    net.addLink(h2, s2, bw=100)
    net.addLink(h3, s2, bw=100)
    net.addLink(h4, s3, bw=100)

    # Switch - Switch (선형 토폴로지)
    net.addLink(s1, s2, bw=100)
    net.addLink(s2, s3, bw=100)

    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
