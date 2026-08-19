;; ─────────────────────────────────────────────────────────────────────
;; The fleet entrance, declared.
;;
;; This is the whole configuration of a login manager as DATA — no code path
;; branches on it, and nothing here is a string a shell will re-split.
;;
;; ── TWO THINGS THIS FILE CANNOT SAY, AND THAT IS THE POINT ───────────
;;
;;   1. It cannot give seat-lab a VT. VTs exist only on seat0 (world-fact
;;      W8), and lowering refuses the combination by name — try it and read
;;      the error, which tells you to use :kind :seatless.
;;
;;   2. It cannot autologin AND restart-on-exit. greetd ships those as a
;;      boolean pair its own nix module has to couple by hand; here the
;;      autologin arm has no restart field to lower into.
;;
;; ── AND ONE NAMING RULE THAT WILL BITE ───────────────────────────────
;;
;;   VALUES lowercase with NO separator (:sealedmemfd, never :sealed-memfd);
;;   FIELD NAMES take snake -> kebab (:window-secs). Two opposite rules in one
;;   language. Every enum value below is deliberately a single word so the
;;   distinction cannot be got wrong.
;; ─────────────────────────────────────────────────────────────────────

(defmukae
  :name "fleet-entrance"

  :seats
  ((defseat
     :id "seat0"
     ;; The one seat that can have a VT, and it takes it: a getty holding
     ;; tty1 is stopped rather than raced.
     :console (defconsole :kind :vt
                          :number 1
                          :switch :required
                          :conflicts "getty@tty1.service")
     :greeter-user "mukae"
     :pam (defpam :user "mukae"
                  :greeter "mukae-greeter"
                  :autologin "mukae-autologin"))

   (defseat
     :id "seat-lab"
     ;; Seatless, necessarily. This is not a limitation of mukae — a seat
     ;; that is not seat0 has no VTs on Linux, full stop.
     :console (defconsole :kind :seatless)
     :greeter-user "mukae"
     :pam (defpam :user "mukae"
                  :greeter "mukae-greeter"
                  :autologin "mukae-autologin")))

  :auth
  (defauthpolicy
    :name "default"
    ;; A greeter that exits and stays gone is a machine with no way in, so
    ;; the restart policy is the recoverable one.
    :startup (defstartup :mode :greeter :restart :always)
    :retry (defretry :attempts 5 :window-secs 60 :backoff :exponential)))
