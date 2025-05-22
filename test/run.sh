#!/bin/bash

exec=$1
if [ -z "$exec" ]; then
	exec=famine
fi

# # Dont run win as root !
# if [ "$(id -u)" -eq 0 ]; then
#     echo "Do not run as root"
#     exit 1
# fi

signature="Famine version 1.0 (c)oded by mbucci-jdecorte"
target1="/tmp/test"
target2="/tmp/test2"
logfile="test.log"
winebase="/root/.wine/drive_c"

dir1=$winebase/$target1
dir2=$winebase/$target2

rm -rf $logfile

if ! command -v wine >/dev/null 2>&1; then
    echo "Wine is not installed."
    exit 1
fi

setup()
{
    rm -rf $dir1 $dir2
    mkdir -p $dir1 $dir2
}


is_all_infected()
{
    for dir in "$dir1" "$dir2"; do
        for file in "$dir"/*; do

            if ! (file "$file" | grep -q "PE32+"); then
                continue
            fi

            # strings "$file" | grep -q "$signature"
            if strings "$file" | grep -q "$signature"; then
                echo "✅ Signature found in $file" >> $logfile
            else
                assertEquals "Signature not found in $file" 0 $?
                echo "❌ Signature not found in $file" >> $logfile
            fi

        done
    done
}

run_famine()
{
    wine "$exec"
    local ret=$?
    assertEquals "'$exec' did not exit cleanly" 0 "$ret"
    if [ $ret -ne 0 ]; then
        exit 1
    fi
}

# Tests -------------


test_basic()
{
    setup

    cp -r $winebase/windows/system32/net.exe $dir1/.
    cp -r $winebase/windows/syswow64/net.exe $dir2/.

    run_famine
    assertEquals 0 $?

    is_all_infected
}


test_all_files_infected()
{
    setup

    cp -r $winebase/windows/system32/*.exe $dir1/.
    cp -r $winebase/windows/syswow64/*.exe $dir2/.

    run_famine
    assertEquals 0 $?

    is_all_infected
}

test_check_double_infection()
{
    setup

    cp -r $winebase/windows/system32/net.exe $dir1/.
    cp -r $winebase/windows/syswow64/net.exe $dir2/.

    run_famine
    assertEquals 0 $?

    run_famine
    assertEquals 0 $?

    infection_count=$(strings "$dir1/net.exe" | grep "$signature" | wc -l)
    if [ "$infection_count" -eq 2 ]; then
        echo "❌ Double infection" >> "$logfile"
        assertEquals "Double infection" 1 "$infection_count"
    else
        echo "✅ No double infection" >> "$logfile"
    fi
}

# test_rerun_infection()
# {
#     setup

#     cp -r $winebase/windows/system32/net.exe $dir1/.
#     cp -r $winebase/windows/syswow64/net.exe $dir2/.

#     run_famine
#     assertEquals 0 $?

#     cp -r $winebase/windows/system32/net.exe $dir1/a.exe
#     cp -r $winebase/windows/syswow64/net.exe $dir2/b.exe

#     wine $winebase/windows/system32/net.exe
#     assertEquals 0 $?

#     is_all_infected
# }





. shunit2