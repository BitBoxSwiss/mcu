Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/precise32"

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    sudo locale-gen UTF-8 
    sudo add-apt-repository ppa:terry.guo/gcc-arm-embedded -y
    sudo apt-get update
    sudo apt-get install -y cmake gcc-arm-none-eabi
  SHELL
  
  config.vm.provision "shell", run: "always", privileged: false, inline: <<-SHELL
    mkdir -p /vagrant/build
    cd /vagrant/build
    rm -rf * && cmake .. -DBUILD_TYPE=firmware && make
  SHELL
end
