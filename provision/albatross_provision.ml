(* (c) 2017 Hannes Mehnert, all rights reserved *)

let asn_version = `AV2

let timestamps validity =
  let now = Ptime_clock.now () in
  match Ptime.add_span now (Ptime.Span.of_int_s (Duration.to_sec validity)) with
  | None -> Error (`Msg "span too big - reached end of ptime")
  | Some exp -> Ok (now, exp)

let rec safe f arg =
  try Ok (f arg) with
  | Unix.Unix_error (Unix.EINTR, _, _) -> safe f arg
  | Unix.Unix_error (e, _, _) -> Error (`Msg (Unix.error_message e))

(* TODO: is this useful elsewhere? *)
let append name data =
  let open Rresult.R.Infix in
  let buf = Bytes.unsafe_of_string data in
  let nam = Fpath.to_string name in
  safe Unix.(openfile nam [ O_APPEND ; O_CREAT ; O_WRONLY ]) 0o644 >>= fun fd ->
  let len = String.length data in
  let rec go off =
    let l = len - off in
    safe (Unix.write fd buf off) l >>= fun w ->
    if l = w then Ok ()
    else go (w + off)
  in
  go 0 >>= fun () ->
  safe Unix.close fd

let key_ids pub issuer =
  let auth = (Some (X509.Public_key.id issuer), [], None) in
  [ (false, `Subject_key_id (X509.Public_key.id pub)) ; (false, `Authority_key_id auth) ]

let sign ?dbname ?certname extensions issuer key csr delta =
  let open Rresult.R.Infix in
  (match certname with
   | Some x -> Ok x
   | None ->
     (try Ok (List.find (function `CN _ -> true | _ -> false) (X509.CA.info csr).X509.CA.subject)
      with Not_found -> Error (`Msg "unable to discover certificate name")) >>= function
     | `CN name -> Ok name
     | _ -> Error (`Msg "cannot happen")) >>= fun certname ->
  timestamps delta >>= fun (valid_from, valid_until) ->
  let extensions =
    match dbname with
    | None -> extensions (* evil hack to avoid issuer + public key for CA cert *)
    | Some _ ->
      match key with
      | `RSA priv ->
        let capub = `RSA (Nocrypto.Rsa.pub_of_priv priv) in
        extensions @ key_ids (X509.CA.info csr).X509.CA.public_key capub
  in
  let cert = X509.CA.sign csr ~valid_from ~valid_until ~extensions key issuer in
  (match dbname with
   | None -> Ok () (* no DB! *)
   | Some dbname ->
     append dbname (Printf.sprintf "%s %s\n" (Z.to_string (X509.Certificate.serial cert)) certname)) >>= fun () ->
  let enc = X509.Certificate.encode_pem cert in
  Bos.OS.File.write Fpath.(v certname + "pem") (Cstruct.to_string enc)

let priv_key ?(bits = 2048) fn name =
  let open Rresult.R.Infix in
  let file = match fn with
    | None -> Fpath.(v name + "key")
    | Some f -> Fpath.v f
  in
  Bos.OS.File.exists file >>= function
  | false ->
    Logs.info (fun m -> m "creating new RSA key %a" Fpath.pp file) ;
    let priv = `RSA (Nocrypto.Rsa.generate bits) in
    Bos.OS.File.write ~mode:0o400 file (Cstruct.to_string (X509.Private_key.encode_pem priv)) >>= fun () ->
    Ok priv
  | true ->
    Bos.OS.File.read file >>= fun s ->
    Rresult.R.reword_error (function `Parse e -> `Msg e)
      (X509.Private_key.decode_pem (Cstruct.of_string s))

open Cmdliner

let nam =
  let doc = "Name to provision" in
  Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"VM")

let cacert =
  let doc = "cacert" in
  Arg.(required & pos 1 (some file) None & info [] ~doc ~docv:"CACERT")

let key =
  let doc = "Private key" in
  Arg.(value & opt (some file) None & info [ "key" ] ~doc)

let db =
  let doc = "Database" in
  Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"DB")

let mem =
  let doc = "Memory to provision" in
  Arg.(required & pos 2 (some int) None & info [] ~doc ~docv:"MEM")
