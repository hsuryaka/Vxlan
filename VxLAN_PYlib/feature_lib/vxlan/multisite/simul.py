 def trmTrafficTestConnfigure(uut,port_hdl_src,port_hdl_rcver_list,pps,mcast_address,test_vlan_scale):
    log.info(banner("------trmTrafficConfigureSpirent-----"))
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'own' in line:
                return 0
            else:
                for vrf in line.split():
                    if 'vxlan-' in vrf:
                        vrf = vrf.replace("[","").replace("]","")
                        log.info('vrf is %r',vrf)
                        vrf_list.append(vrf)

    if not 'Nil' in test_vlan_scale:
        test_vlan_scale = []
        for i in range(0,test_vlan_scale):
    	    test_vrf_list.append(choice(vrf_list))
    else:
    	test_vrf_list = vrf_list

    for vrf in test_vrf_list:
        log.info('---------vrf is %r-----------',vrf)
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            ip_sa= str(ip_address(ip1)+randint(10,149))
                            log.info('---------vlan is %r-----------',vlan)
                            log.info('---------ip_sa is %r-----------',ip_sa)
                            log.info('---------mcast_address is %r-----------',mcast_address)
                            log.info('---------Going to mcastTrafficConfig-----------')
                            mcastTrafficConfig(port_hdl_src,vlan,ip_sa,mcast_address,1000)
                            check = check + 1
                            mcast_address = str(ip_address(mcast_address)+1)

    for vrf in test_vrf_list:
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            for port_handle in port_hdl_rcver_list:
                                host_ip= str(ip_address(ip1)+randint(150,250))
                                log.info('---------vlan is %r-----------',vlan)
                                log.info('---------host_ip is %r-----------',host_ip)
                                log.info('---------mcast_address is %r-----------',mcast_address)
                                log.info('---------Going to mcastTrafficConfig-----------')       
                                IgmpHostCreate(port_handle=port_handle,\
                                vlan = vlan,
                                vlan_scale = count,
                                host_ip =host_ip,
                                mcast_group = mcast_address,
                                mcast_group_scale = 1)

        mcast_address = str(ip_address(mcast_address)+1)

'''

def trmTrafficTestConnfigure(uut,port_hdl_src,port_hdl_rcver_list,pps,mcast_address,test_vlan_scale):
    log.info(banner("------trmTrafficConfigureSpirent-----"))
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'own' in line:
                return 0
            else:
                for vrf in line.split():
                    if 'vxlan-' in vrf:
                        vrf = vrf.replace("[","").replace("]","")
                        log.info('vrf is %r',vrf)
                        vrf_list.append(vrf)

    if not 'Nil' in str(test_vlan_scale):
        test_vrf_list = []
        for i in range(0,test_vlan_scale):
            test_vrf_list.append(choice(vrf_list))
    else:
        test_vrf_list = vrf_list

    for vrf in test_vrf_list:
        log.info('---------vrf is %r-----------',vrf)
        count = uut.execute('show ip int br vrf {vrf} | incl Vlan | exc forward | count'.format(vrf=vrf))
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        check = 1
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        if check == 1:
                            vlan_list.append(line.split()[0].replace("Vlan",""))
                            vlan=line.split()[0].replace("Vlan","")
                            ip_list.append(line.split()[1])
                            ip1 = line.split()[1]
                            ip_sa= str(ip_address(ip1)+randint(10,149))
                            log.info('---------vlan is %r-----------',vlan)
                            log.info('---------ip_sa is %r-----------',ip_sa)
                            log.info('---------mcast_address is %r-----------',mcast_address)
                            log.info('---------Going to mcastTrafficConfig-----------')
                            mcastTrafficConfig(port_hdl_src,vlan,ip_sa,mcast_address,1000)
                            check = check + 1
                            for port_handle in port_hdl_rcver_list:
                                host_ip= str(ip_address(ip1)+randint(150,250))
                                log.info('---------vlan is %r-----------',vlan)
                                log.info('---------host_ip is %r-----------',host_ip)
                                log.info('---------mcast_address is %r-----------',mcast_address)
                                log.info('---------Going to mcastTrafficConfig-----------')       
                                IgmpHostCreate(port_handle=port_handle,\
                                vlan = vlan,
                                vlan_scale = count,
                                host_ip =host_ip,
                                mcast_group = mcast_address,
                                mcast_group_scale = 1)
                            mcast_address = str(ip_address(mcast_address)+1)
                            
        mcast_address = str(ip_address(mcast_address)+1)






 



