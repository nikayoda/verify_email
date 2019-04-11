# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
    config.vm.box = "ubuntu/xenial64"
    config.vm.network "public_network", :bridge => "eth0", ip:"45.58.39.23", :auto_config => "false", :netmask => "255.255.255.0"

    config.vm.provider "virtualbox" do |vb|
        vb.memory = "1024"
        vb.cpus = "1"
    end

    Vagrant.configure("2") do |cfg|
        cfg.vm.synced_folder "/root/verify", "/root/verify"
    end

     config.vm.provision "shell", inline: <<-SHELL
       sudo apt-get update
       sudo apt-get install -y apache2
     SHELL
end
