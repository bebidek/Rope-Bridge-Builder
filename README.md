Skrypty budujące są przeznaczone dla systemu Arch Linux. Zostały przetestowane na maszynie wirtualnej dostępnej pod adresem: <https://gitlab.archlinux.org/archlinux/arch-boxes/-/packages>.

# STRUKTURA KATALOGÓW
`scripts` - cały kod napisany w Pythonie, w szczególności transformator\
`examples` - programy testowe\
`asm` - biblioteka placeholder.o która wprowadza do plików ELF potrzebne sekcje\
`patches` - pliki zawierające patche oraz parametry kompilacji (.config)

# PRZYGOTOWANIE ŚRODOWISKA
**UWAGA** Opisane poniżej skrypty istotnie wpływają na system (np. instalują nowe jądro). Należy je uruchamiać wyłącznie w dedykowanym środowisku testowym (np. na maszynie wirtualnej).

Żeby skonfigurować system, należy po kolei uruchmić następujące skrypty: 

`prepare_env.sh` - pobiera niezbędne paczki oraz przygotowuje środowisko python venv.
    

`prepare_libs.sh` - pobiera oraz kompiluje biblioteki potrzebne do kompilacji programów przykładowych.

    
`prepare_valgrind.sh` - pobiera, patch'uje i kompiluje Valgrind.

`prepare_kernel.sh` - pobiera, patch'uje, kompiluje oraz instaluje jądro.
    
Po ostatnim trzeba oczywiście przeładować system tak, żeby korzystał z nowego kernela (linux-6.10).
    
# TESTOWANIE
Przed testowaniem upewnij się, że pracujesz na zmodyfikowanym kernelu obsługującym RBB oraz, że środowisko rbb_venv jest aktywne.

1. Przejdź do wybranego folderu z programem testowym, np. `examples/dummy`.
2. `make clean && make`. To spowoduje kompilację programu, następnie zostanie uruchomiony analizator a na koniec transformator. W efekcie powinny pojawić się dwa pliki `old_dummy` oraz `new_dummy` (lub analogiczne dla innego katalogu).
3. `../../scripts/benchmark.py dummy 32 [output.csv]` uruchomi pomiar wydajności, wykonując po 32 uruchomienia starej i nowej wersji, naprzemiennie.
