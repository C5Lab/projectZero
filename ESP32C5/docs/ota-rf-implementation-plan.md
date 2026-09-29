# Plan OTA: JanOS i Tab5 — do omówienia

Status: plan omówiony; wykonano poprawki wspólnego mechanizmu JanOS i dodano
ręczny, jednorazowy wybór repo RF. Automatyczna identyfikacja RF i Tab5 pozostają
do wykonania. Praca odbywa się na `development`, zgodnie z preferencją użytkownika.
Data: 2026-09-29.

## Cel i podział odpowiedzialności

Dwa etapy dostarczenia: **1. JanOS**, następnie **2. Tab5**. Przed etapem 1
uzgadniamy wspólny kontrakt identyfikacji i statusu. To przygotowanie obu etapów,
nie trzeci etap wdrożenia.

Monster sam wybiera repozytorium, łączy się z Wi-Fi, pobiera i zapisuje obraz.
Tab5 jest pilotem po UART: rozpoznaje urządzenie, wysyła komendy i pokazuje wynik.
Nie dodajemy pobierania binów ani flashera ESP32-C5 do Tab5. Aktualizacja samego
Tab5/ESP32-P4 nie należy do tego zakresu.

Repozytoria lokalne:

- JanOS: `C:/Users/mati/Documents/GitHub/projectZero/ESP32C5`.
- Tab5: `C:/Users/mati/Documents/GitHub/M5MonsterC5-Tab5`.

## Stan potwierdzony w kodzie

JanOS: `main/main.c` zawiera wybór źródła, pobieranie metadanych GitHub,
transfer HTTPS OTA, zapis kanału i potwierdzenie startu. Testy hostowe:
`tests/test_ota_flow.py`, adapter `tests/ota_host.c`, oraz nowy test startu
`tests/test_ota_boot.py`. Po pierwszych poprawkach: 47 testów przechodzi,
bez expectedFailure; nie oznacza to testu sprzętu.

Tab5: sekcja Monster OTA w `main/main.c`:

- `ota_send_cmd`, `ota_check_btn_cb`, `ota_list_btn_cb` zlecają OTA Monsterowi.
- `ota_channel_changed_cb` pokazuje ustawiony kanał już po wysłaniu polecenia,
  zanim potwierdzi go urządzenie.
- `ota_handle_line` i `ota_monitor_task` przetwarzają odpowiedzi.
- `tab_context_t` ma `janos_version`, `janos_rf_version`, `has_subghz` i dane
  działającej aplikacji, ale nie zweryfikowany model/profile OTA.
- `check_subghz_status_for_tab` wykrywa obsługę `subghz_status`; timeout nie
  dowodzi, że podłączono klasycznego Monstera.
- `check_version_for_tab` odczytuje wersję lub korzysta z zapisanej informacji
  z bootu. Przed nową sesją aktualizacji potrzebne jest odświeżenie tożsamości.
- Aktualny wybór celu OTA preferuje Grove, następnie USB, następnie MBus.
  Aktualizacja musi zostać przypisana do konkretnego urządzenia i połączenia.

Release RF `1.7.5` ma komplet binów i jest zwracany przez GitHub `releases/latest`.
Nie potrzebujemy osobnego manifestu do wersjonowania. Oba warianty mają nazwę
projektu `projectZero`, więc nie jest ona identyfikatorem modelu.

## Ustalenia przed implementacją

1. **Identyfikacja sprzętu.** Ustalić wiarygodny sposób przypisania
   `classic|rf|unknown`. Sprawdzić `board_name` na RF i znaczenie wartości eFuse.
   Etykieta użytkownika, wersja, brak odpowiedzi i sama funkcja Sub-GHz nie są
   wystarczającym potwierdzeniem. Oznaczenie builda opisuje jego przeznaczenie;
   nie traktować go automatycznie jako dowodu modelu fizycznej płytki.
2. **Zgodność starszego firmware.** Rekomendacja: pełne nowe OTA wymaga
   potwierdzonej identyfikacji i obsługi właściwego profilu. Starsze/nieznane
   firmware dostaje czytelny komunikat, bez automatycznego wyboru klasycznego.
   Ewentualny ręczny tryb zgodności wymaga osobnego uzgodnienia.
3. **Build RF.** Źródeł RF lokalnie nie ma. Zmiany mechanizmu/protokołu muszą
   trafić do builda publikowanego przez autora RF. Można przygotować i testować
   profil u nas, ale nie ogłaszać działającego RF OTA na podstawie samego release'u.
4. **Kanały.** Rekomendacja: klasyczny `main/dev`, RF początkowo tylko `main`.
   `dev` na RF zgłasza brak obsługi; nie przełącza na klasyczne biny.

## Proponowany kontrakt JanOS ↔ Tab5

Zachować istniejące komendy i czytelne logi. Rozszerzyć `ota_info` o osobny,
wersjonowany rekord maszynowy z polami:

| Pole | Znaczenie |
|---|---|
| Wersja protokołu | Pozwala rozpoznać wspieraną strukturę odpowiedzi |
| Identyfikator urządzenia | Wiąże odpowiedź z fizycznym urządzeniem, nie samym portem |
| Wariant | `classic`, `rf` albo `unknown` |
| Wersja aplikacji | Odczyt z deskryptora działającego obrazu |
| Profil źródła | Faktycznie wybrane repozytorium OTA |
| Kanał i dostępne kanały | Stan potwierdzony przez urządzenie |
| Stan bootu | Weryfikacja nowego obrazu trwa / obraz potwierdzony |
| Możliwości OTA | Czy firmware obsługuje aktualizację tego wariantu |

Finalną składnię rekordu uzgadniamy przed pisaniem parserów. Tab5 nie wysyła
arbitralnego URL ani polecenia zmiany modelu. Firmware wybiera źródło, a Tab5
sprawdza zgodność przed wysłaniem polecenia aktualizacji.

## Etap 1 — JanOS

### J1. Jawne profile i stabilny kontekst pojedynczej aktualizacji

Miejsca: stałe OTA, `ota_start_check`, `ota_check_task`, funkcje pobierania
release'ów, `ota_build_branch_url`, `cmd_ota_list`, `cmd_ota_info` w `main/main.c`.

- Jeden wybór profilu dla check/latest/tag/list/dev: klasyczny
  `C5Lab/projectZero`, RF `elpadrino26/janosrf-web-flasher`.
- Zamrozić profil, kanał i politykę wersji w argumentach zadania przy przyjęciu
  żądania; zmiana ustawień później nie zmienia rozpoczętej operacji.
- Rozróżniać nieznany wariant, nieobsługiwany kanał i brak wydania.
- Nie używać klasycznego źródła jako zastępstwa po błędzie RF.
- Zapewnić pojedyncze zadanie OTA; ustalić blokowanie komend zmieniających radio
  lub slot startowy w trakcie transferu.

Testy: tablica wariant × kanał × check/latest/tag/list, błędy źródła, zmiana
ustawień po przyjęciu żądania, duplikaty i ponowienie po błędzie.

### J2. Wersje, kanały i walidacja pobierania

Miejsca: `ota_parse_version`, `ota_is_newer_version`, `ota_perform_https_update`,
`ota_fetch_latest_release`, `ota_fetch_release_by_tag`, `cmd_ota_channel`.

- Uzgodnić ścisły format wersji, w tym `v` i prerelease. Nie akceptować fragmentu
  błędnego napisu jako poprawnej wersji.
- W release'ach porównać wersję z metadanych z deskryptorem obrazu.
- `main/latest`: obraz nowszy od działającego. Konkretny tag: dopuszczony
  downgrade/reinstalacja, nadal wymagana zgodność metadanych z binem.
- Klasyczny `dev`: zachować świadome pomijanie warunku nowszej wersji.
- Weryfikować rozmiar i SHA-256 z metadanych assetu przed aktywacją; określić
  zachowanie wobec starszych wydań bez digestu przed włączeniem wymagalności.
  Digest całego assetu nie jest zamienny z `app_elf_sha256` w deskryptorze.
- Normalizować kanał; aktywną wartość zmieniać dopiero po poprawnym zapisie NVS.
- Odrzucać zbyt długie parametry i odpowiedzi zamiast je obcinać.

Testy: znane błędy OTA-01..06, niespójny tag/obraz, uszkodzony plik, rozmiar,
hash, niepoprawne dane GitHub, TLS/HTTP i brak pamięci. Dodać wykonawcze testy
parsera metadanych — obecny adapter zastępuje tę granicę gotowymi danymi.

### J3. Uruchomienie po OTA i oczekiwanie na sieć

Miejsca: `ota_mark_valid_if_pending`, `app_main`, obsługa `wifi_connect ... ota`
i `IP_EVENT_STA_GOT_IP`.

- Potwierdzać nowy obraz po wymaganej inicjalizacji, w okolicy `BOARD READY`.
- SD, wyświetlacz, GPS i Internet nie są warunkiem poprawnego startu.
- Odróżnić gotowość aplikacji od samego upływu czasu. Limit pierwszego startu
  dobrać na podstawie pomiarów; brak potwierdzenia sam nie wywołuje resetu.
- Zaprojektować kontrolowany reset/rollback po błędzie krytycznym lub
  przekroczeniu limitu oraz obsłużyć brak poprawnego obrazu zapasowego.
- Do potwierdzenia bootu odrzucać nowe OTA i ręczną zmianę slotu. Zachować
  dostęp do diagnostyki i konsoli.
- Żądanie OTA po połączeniu zachować do przyjścia IP w ograniczonym czasie;
  wyczyścić je przy błędzie, anulowaniu lub zmianie sesji sieciowej. Jedno IP
  uruchamia najwyżej jedną aktualizację.

Testy: opóźnione DHCP, duplikaty zdarzeń, utrata sieci, startup success/failure,
brak opcjonalnych peryferiów i błąd potwierdzenia obrazu. Sam test helpera nie
potwierdza właściwej kolejności w `app_main` — potrzebny również test integracyjny.

### Warunek zakończenia etapu 1

Testy hostowe i build właściwego targetu ESP32-C5 przechodzą; poprawione problemy
tracą adnotację expectedFailure. Próba na klasycznym Monsterze potwierdza oba
sloty i rollback. Obsługa RF pozostaje niedopuszczona do użycia, dopóki zgodny
build RF i identyfikacja nie zostaną sprawdzone. To jawny warunek integracji,
nie powód do blokowania niezależnych poprawek klasycznego OTA.

## Etap 2 — Tab5

Miejsca: `main/main.c`: `tab_context_t`, wykrywanie/weryfikacja wersji,
`show_ota_page`, `ota_send_cmd`, `ota_channel_changed_cb`, `ota_check_btn_cb`,
`ota_handle_line`, `ota_monitor_task`. Dokumentacja: `docs/Monster_OTA.md`.
Testy parsera i przejść stanów w `tests/`; emulator weryfikuje widoczne zachowanie,
ale nie zastępuje testów rzeczywistego parsera i transportu.

### T1. Tożsamość urządzenia i wybór celu

- Przechowywać wariant, capabilities i potwierdzony profil osobno dla Grove,
  USB i MBus. Nie zamieniać `has_subghz` w autorytet wyboru obrazu.
- Odświeżyć identyfikację przed aktualizacją i po restarcie. Unieważniać cache
  po odłączeniu, zmianie płytki i zmianie sesji transportu.
- Przypisać operację do konkretnego połączenia i identyfikatora. Nie przenosić
  jej na inny port, gdy pierwotny znika. Pokazać model i połączenie użytkownikowi.
- Brak potwierdzenia profilu/capabilities blokuje start aktualizacji RF.

Testy: klasyczny/RF/unknown/legacy, fragmentacja odpowiedzi, timeout, spóźniona
odpowiedź, dwie płytki jednocześnie, wymiana płytki na tym samym porcie.

### T2. Sterowanie OTA zgodne z potwierdzonym stanem

- Pozostawić pobieranie i zapis na Monsterze; wysyłać istniejące polecenia.
- Pokazywać faktyczny profil i tylko obsługiwane kanały.
- Zmiana kanału: stan oczekiwania, potwierdzenie urządzenia, dopiero potem
  zmiana stanu UI; przy błędzie powrót do ostatniego potwierdzonego kanału.
- Nie wysyłać aktualizacji, gdy zmiana kanału/identyfikacja nie została zakończona.
- Lista wydań pochodzi z wybranego przez urządzenie profilu.

Testy: kanał zapisany/odrzucony/timeout, brak dev na RF, właściwy port dla każdej
komendy, brak wysłania OTA przy niezgodnym profilu i opóźnionym potwierdzeniu.

### T3. Potwierdzenie wyniku po restarcie

- Rozdzielić: pobieranie, zapis zakończony, restart, sprawdzenie nowej aplikacji,
  sukces lub rollback/błąd/brak potwierdzenia.
- `OTA: update applied, restarting` oznacza zakończenie instalacji i początek
  oczekiwania na nowy start; nie dowodzi jeszcze zdrowia nowej aplikacji.
- Po reconnect sprawdzić ten sam wariant/urządzenie, docelową wersję, profil
  oraz stan potwierdzenia bootu. Cisza i dowolny napis restart nie oznaczają sukcesu.
- Limit oczekiwania kończy się wynikiem niepotwierdzonym, bez automatycznego
  ponowienia flashowania. Odtworzyć pollery i wygaszanie ekranu na każdym wyjściu.

Testy: poprawny powrót, rollback do starej wersji, brak powrotu, inna płytka,
przerwany UART, błąd po pobraniu, odblokowanie UI/pollerów po zakończeniu.

## Końcowe próby sprzętowe

| Próba | Kryterium |
|---|---|
| Klasyczny: dwa kolejne wydania z Tab5 | Poprawny profil i naprzemienne sloty |
| RF: dwa kolejne wydania z Tab5 | Oba pobrane z RF; profil przetrwał pierwszy update |
| Odłączenie Wi-Fi i zasilania w różnych fazach | Bootuje kompletny obraz; zachowane dane |
| Wymuszony błąd przed gotowością nowej aplikacji | Powrót do starego obrazu; Tab5 nie ogłasza sukcesu |
| Brak SD/ekranu/Internetu po restarcie | Sprawny firmware może zostać potwierdzony |
| Niedostępny release RF | Czytelny błąd; zero prób instalacji klasycznej wersji |
| Dwie płytki, różne porty, wymiana płytki | Aktualizowana wyłącznie wskazana płytka |

Testy utraty zasilania/rollbacku wykonujemy na urządzeniu testowym z dostępnym
odzyskiwaniem przez USB. Testy hostowe nie potwierdzają tych właściwości.

## Proponowana kolejność zmian i rozmowy

Małe, osobno sprawdzane zmiany: J1 → J2 → J3 → odbiór JanOS → T1 → T2 → T3 →
próby zintegrowane. Każda zmiana ma najpierw test odtwarzający problem, potem
implementację i weryfikację. Nie mieszamy tego z przebudową całego `main.c`.

Do decyzji w rozmowie: pewny identyfikator RF i klasycznego, sposób dostarczenia
zmian do buildów RF, zachowanie starego firmware, polityka prerelease/digestu
oraz pierwszy zakres napraw. Rekomendowany pierwszy zakres to walidacja
release–bin, poprawny zapis kanału i potwierdzenie zdrowego startu.

## Pierwsza poprawka po akceptacji

Wykonano niezależny od RF zakres: zgodność wersji release–bin, ścisłe wersje
z kolejnością prerelease, normalizację i transakcyjny zapis kanału, zachowanie
kanału wybranego w chwili zlecenia, odrzucanie za długich tagów oraz późniejsze
potwierdzanie obrazu po wymaganej inicjalizacji UART/konsoli/GPIO. Do tego czasu
zablokowane są `ota_check` i `ota_boot`; błąd potwierdzenia nie zwalnia blokady.
Nie dodano arbitralnego timeoutu startu ani resetu bez pomiarów na sprzęcie.

Pozostały zakres J1–J3 nadal obejmuje automatyczną identyfikację/profile RF, kontrakt `ota_info`,
walidację metadanych/hash/rozmiaru, pełną synchronizację konkurencyjnych operacji,
opóźnione DHCP i politykę resetu/rollbacku. Cały etap 1 nie jest jeszcze odebrany.
Etap 2 (Tab5) pozostaje bez zmian.

Egzemplarz RF użytkownika działa na 1.7.1 i odpowiada na `subghz_status`.
Pozwala to zaplanować próbę do 1.7.5, ale źródło OTA starego firmware wymaga
sprawdzenia. Log zgłasza nieważne otadata (`run=ota_0 state=-1 next=ota_1`),
więc nie stanowi dowodu istnienia poprawnego obrazu zapasowego. Nowe poprawki
lokalnego JanOS nie zmieniają już opublikowanych binów RF.

## Ręczny wybór RF — kolejny zaakceptowany zakres

Po wgraniu lokalnego klasycznego 1.7.5 użytkownik potwierdził brak komend
`board_name`/`subghz_status`, działający slot ota_0 w stanie VALID i listę wydań
klasycznych. Nie ustalono sposobu flashowania; zgodność sprawdza teraz kod.

- `ota_list rf` pobiera listę wydań RF bez zmiany domyślnego źródła.
- `ota_check rf 1.7.5` jawnie zleca instalację tego wydania, także przy równej
  wersji. `ota_check rf [latest]` wymaga nowszej wersji. RF nie używa dev.
- `ota_info` pokazuje domyślne repo, źródło ręczne RF, offset tablicy i zgodność
  lokalnego układu. Nie deklaruje wykrycia fizycznego modelu.
- Kontrola wymaga tablicy 0x10000 i partycji RF. Następnie porównuje biny
  bootloadera i tablicy z tego samego release'u z lokalnym flashem. IDF sprawdza
  poprawność i pełną długość zainstalowanego bootloadera; krótki zgodny fragment
  pobranego pliku nie wystarczy. Zapisywana jest tylko aplikacja.
- Standardowy lokalny build z tablicą 0x8000 zgłasza niezgodność i potrzebę
  przywrócenia RF przez USB. Nie dodano migracji partycji ani builda przejściowego.
- Zmiany nie przechodzą automatycznie do pobranego, zamkniętego firmware RF.

Instrukcja użycia i granice testów: [ota-test-coverage.md](ota-test-coverage.md).
