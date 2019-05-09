# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/trusty64"

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    sudo locale-gen UTF-8
    sudo add-apt-repository ppa:team-gcc-arm-embedded/ppa -y
    sudo apt-get update
    sudo apt-get install -y cmake git gcc-arm-embedded=8-2018q4-major~trusty1
  SHELL

  config.vm.provision "shell", run: "always", privileged: false, inline: <<-SHELL
    mkdir -p /vagrant/build-vagrant
    cd /vagrant/build-vagrant
    rm -rf * && cmake .. -DBUILD_TYPE=firmware && make
  SHELL
end
