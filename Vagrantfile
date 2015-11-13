# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty32"

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    sudo locale-gen UTF-8 
    sudo add-apt-repository ppa:terry.guo/gcc-arm-embedded -y
    sudo apt-get update
    sudo apt-get install -y cmake git gcc-arm-none-eabi
    sudo cp /vagrant/src/drivers/lib/libssp* /usr/lib/gcc/arm-none-eabi/4.9.3/armv7e-m/
  SHELL
  
  config.vm.provision "shell", run: "always", privileged: false, inline: <<-SHELL
    mkdir -p /vagrant/build
    cd /vagrant/build
    rm -rf * && cmake .. -DBUILD_TYPE=firmware && make
  SHELL
end
