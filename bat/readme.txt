进去之后先su root输密码
然后运行netns_my_init.sh
然后想要看R1R3的调试信息就分别在不同的终端里运行birdR(1/3).sh
直接跑的话就bird.sh
然后运行router.sh
要把birdR1.conf和birdR3.conf 放在/etc目录下面
所有文件都解压到/home/pi(也就是默认进去的目录)
/home/pi这个文件夹下要有你的Router-Lab文件夹
运行完router.sh
就ip netns exec PC1 ping 192.168.5.1测试连通性就行了