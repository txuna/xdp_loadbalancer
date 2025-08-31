# ubunut init script

sudo apt update && sudo apt upgrade -y

# install zsh
sudo apt install zsh -y
sudo chsh -s $(which zsh)
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting


# install essentials
sudo apt install net-tools pkg-config gcc make m4 libpcap-dev -y


# install golang
wget https://go.dev/dl/go1.25.0.linux-arm64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.0.linux-arm64.tar.gz
export PATH=$PATH:/usr/local/go/bin


# install bpf
sudo apt install llvm clang libbpf-dev -y

sudo apt install linux-headers-`uname -r`
sudo ln -s /usr/include/aarch64-linux-gnu/asm /usr/include