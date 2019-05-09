# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    sudo locale-gen UTF-8
    sudo apt update && sudo apt-get install -y cmake git
    wget -O gcc.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2018q4/gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2;
    tar -xf gcc.tar.bz2
    sudo rsync -a gcc-arm-none-eabi-8-2018-q4-major/ /usr/local/
  SHELL

  config.vm.provision "shell", run: "always", privileged: false, inline: <<-SHELL
    mkdir -p /vagrant/build-vagrant
    cd /vagrant/build-vagrant
    rm -rf * && cmake .. -DBUILD_TYPE=firmware && make
  SHELL
end
