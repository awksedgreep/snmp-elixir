# This Source Code Form is subject to the terms of the
# Mozilla Public License, v. 2.0. If a copy of the MPL was
# not distributed with this file, You can obtain one at
# http://mozilla.org/MPL/2.0/.

defmodule SNMP do
  use Application

  @moduledoc """
  An SNMP client library for Elixir.
  """

  alias SNMP.{
    MIB,
    Utility,
    CommunityCredential,
    USMCredential,
    DiscoveryAgent
  }

  require Logger

  defmacrop sync_get(target, oids, timeout, context) do
    with {:module, :snmpm} <- Code.ensure_loaded(:snmpm) do
      if function_exported?(:snmpm, :sync_get2, 4) do
        quote do
          :snmpm.sync_get2(
            __MODULE__,
            unquote(target),
            unquote(oids),
            [ timeout: unquote(timeout),
              context: unquote(context),
            ]
          )
        end
      else
        quote do
          :snmpm.sync_get(
            __MODULE__,
            unquote(target),
            unquote(context),
            unquote(oids),
            unquote(timeout)
          )
        end
      end
    end
  end

  defmacrop sync_get_next(target, context, oids, timeout) do
    with {:module, :snmpm} <- Code.ensure_loaded(:snmpm) do
      if function_exported?(:snmpm, :sync_get_next2, 4) do
        quote do
          :snmpm.sync_get_next2(
            __MODULE__,
            unquote(target),
            unquote(oids),
            [ timeout: unquote(timeout),
              context: unquote(context),
            ]
          )
        end
      else
        quote do
          :snmpm.sync_get_next(
            __MODULE__,
            unquote(target),
            unquote(context),
            unquote(oids),
            unquote(timeout)
          )
        end
      end
    end
  end

  defmacrop sync_set(target, context, vars_and_vals, timeout) do
    with {:module, :snmpm} <- Code.ensure_loaded(:snmpm) do
      if function_exported?(:snmpm, :sync_set2, 4) do
        quote do
          :snmpm.sync_set2(
            __MODULE__,
            unquote(target),
            unquote(vars_and_vals),
            [ timeout: unquote(timeout),
              context: unquote(context),
            ]
          )
        end
      else
        quote do
          :snmpm.sync_set(
            __MODULE__,
            unquote(target),
            unquote(context),
            unquote(vars_and_vals),
            unquote(timeout)
          )
        end
      end
    end
  end

  defmacrop sync_get_bulk(target, non_repeaters, max_repetitions, oids, timeout, context) do
    with {:module, :snmpm} <- Code.ensure_loaded(:snmpm) do
      if function_exported?(:snmpm, :sync_get_bulk2, 5) do
        quote do
          :snmpm.sync_get_bulk2(
            __MODULE__,
            unquote(target),
            unquote(non_repeaters),
            unquote(max_repetitions),
            unquote(oids),
            [timeout: unquote(timeout), context: unquote(context)]
          )
        end
      else
        quote do
          :snmpm.sync_get_bulk(
            __MODULE__,
            unquote(target),
            unquote(context),
            unquote(non_repeaters),
            unquote(max_repetitions),
            unquote(oids),
            unquote(timeout)
          )
        end
      end
    end
  end

  @type snmp_credential()
    :: CommunityCredential.t()
     | USMCredential.t()

  defmodule CommunityCredential do
    defstruct [
      version: :v1,
      sec_model: :v1,
      community: nil,
    ]

    @type t ::
      %__MODULE__{
        version:   :v1 | :v2,
        sec_model: :v1 | :v2c,
        community: [byte],
      }
  end

  defmodule USMCredential do
    defstruct [
      version:   :v3,
      sec_model: :usm,
      sec_level: :noAuthNoPriv,
      sec_name:  [],
      auth:      :usmNoAuthProtocol,
      auth_pass: nil,
      priv:      :usmNoPrivProtocol,
      priv_pass: nil,
    ]

    @type t ::
      %__MODULE__{
        version:   :v3,
        sec_model: :usm,
        sec_level:
            :noAuthNoPriv
          | :authNoPriv
          | :authPriv,
        sec_name:  [byte],
        auth:
            :usmNoAuthProtocol
          | :usmHMACMD5AuthProtocol
          | :usmHMACSHAAuthProtocol,
        auth_pass: nil | [byte],
        priv:
            :usmNoPrivProtocol
          | :usmDESPrivProtocol
          | :usmAesCfb128Protocol,
        priv_pass: nil | [byte]
      }
  end

  def start,
    do: start(:normal, [])

  def start(_type, args) do
    # snmpm configuration taken from
    # https://github.com/erlang/otp/blob/40de8cc4452dfdc5d390c93860870d4bf4605eb9/lib/snmp/src/manager/snmpm.erl#L156-L196

    mib_cache =
      Application.get_env(:snmp_ex, :mib_cache)

    snmp_conf_dir =
      Application.get_env(:snmp_ex, :snmp_conf_dir)

    snmpm_conf_dir =
      Application.get_env(:snmp_ex, :snmpm_conf_dir)

    _ = File.rm_rf!(mib_cache)
    _ = File.mkdir_p!(mib_cache)

    _ = File.rm_rf!(snmp_conf_dir)
    _ = File.mkdir_p!(snmp_conf_dir)

    _ = File.rm_rf!(snmpm_conf_dir)
    _ = File.mkdir_p!(snmpm_conf_dir)

    snmpm_conf_dir_erl =
      :binary.bin_to_list(snmpm_conf_dir)

    # :snmp_config.write_manager_config(snmpm_conf_dir_erl, [], [
    #   {:port, 5000},
    #   {:engine_id, :"\"mgrEngine\""},
    #   {:max_message_size, 484}
    # ])
    :ok =
      :snmpm_conf.write_manager_config(
        snmpm_conf_dir_erl,
        [
          :snmpm_conf.manager_entry(:max_message_size, 484),
          :snmpm_conf.manager_entry(:port, 5000),
          :snmpm_conf.manager_entry(:engine_id, ~c'mgrEngine')
        ]
      )

    snmpm_conf_dir =
      Application.get_env(:snmp_ex, :snmpm_conf_dir)
      |> :binary.bin_to_list()

    snmpm_opts =
      [ versions: [:v1, :v2, :v3],
        config: [
          dir:    snmpm_conf_dir,
          db_dir: snmpm_conf_dir,
        ],
      ]

    children =
      [ %{id: :snmpm_supervisor,
          start: {
            :snmpm_supervisor,
            :start_link,
            [:normal, snmpm_opts]
          },
        },
        %{id: SNMP.DiscoveryAgent,
          start: {
            SNMP.DiscoveryAgent,
            :start_link,
            []
          },
        },
      ]

    strategy =
      Keyword.get(args, :strategy, :one_for_one)

    sup_opts =
      [ name:     SNMP.Supervisor,
        strategy: strategy,
      ]

    {:ok, _} = result =
      Supervisor.start_link(children, sup_opts)

    user_mod = :snmpm_user_default

    :ok =
      :snmpm.register_user(__MODULE__, user_mod, self())

    _ = update_mib_cache()
    _ = load_cached_mibs()

    result
  end

  defp find_mibs_recursive(dir),
    do: Utility.find_files_recursive(dir, ~r/\.(txt|mib)$/)

  defp change_dirname(path, new_dirname) do
    path
    |> Path.basename()
    |> Path.absname(new_dirname)
  end

  defp change_extension(path, new_extension),
    do: Path.rootname(path) <> new_extension

  defp mib_cache do
    :snmp_ex
    |> Application.get_env(:mib_cache)
    |> Path.expand()
  end

  defp mib_sources,
    do: Application.get_env(:snmp_ex, :mib_sources)

  defp update_mib_cache do
    cache_dir = mib_cache()

    _ =
      case File.exists?(cache_dir) do
        true ->
          _ = File.rm_rf!(cache_dir)
          _ = File.mkdir_p(cache_dir)

        false ->
          _ = File.mkdir_p(cache_dir)
      end

    _ =
      mib_sources()
      |> Stream.map(&Path.expand/1)
      |> Stream.flat_map(&find_mibs_recursive/1)
      |> Enum.uniq()
      |> Enum.map(fn source ->
        destination =
          source
          |> change_dirname(cache_dir)
          |> change_extension(".mib")

        File.cp(source, destination)
      end)

    MIB.compile_all(cache_dir)
  end

  defp load_cached_mibs do
    mib_cache()
    |> Utility.find_files_recursive(~r/\.bin$/)
    |> Enum.map(&load_mib/1)
  end

  defp get_timeout,
    do: Application.get_env(:snmp_ex, :timeout)

#  Temporarily commented.  Will uncomment when needed.
#  defp get_max_repetitions,
#    do: Application.get_env(:snmp_ex, :max_repetitions)

  defp get_delimiter_by_family(4), do: "."
  defp get_delimiter_by_family(6), do: ":"

  defp get_host_by_name(hostname) do
    result =
      hostname
      |> :binary.bin_to_list()
      |> :inet.gethostbyname()

    with {:ok, {_, _, _, _, family, [address | _]}}
           <- result
    do
      delimiter = get_delimiter_by_family(family)

      address_string =
        address
        |> Tuple.to_list()
        |> Enum.join(delimiter)

      {:ok, address_string}
    end
  end

  defp parse_ip(address) do
    case NetAddr.ip(address) do
      {:error, _} = error ->
        error

      netaddr ->
        {:ok, netaddr}
    end
  end

  defp resolve_host_to_netaddr(host) do
    with {:error, _} <- parse_ip(host),
         {:ok, ip} <- get_host_by_name(host),
      do: parse_ip(ip)
  end

  defp resolve_host_in_uri(uri) do
    with {:ok, netaddr}
           <- resolve_host_to_netaddr(uri.host)
    do
      ip_uri =
        %{uri |
          host: "#{NetAddr.address(netaddr)}"
        }

      {:ok, ip_uri}
    end
  end

  defp get_transport_from_netaddr(%NetAddr.IPv4{}),
    do: :transportDomainUdpIpv4

  defp get_transport_from_netaddr(%NetAddr.IPv6{}),
    do: :transportDomainUdpIpv6

  defp get_usm_user_config(credential, engine_id) do
    auth      = credential.auth
    auth_pass = credential.auth_pass
    priv      = credential.priv
    priv_pass = credential.priv_pass

    hash_algo =
      case auth do
        :usmNoAuthProtocol      -> nil
        :usmHMACMD5AuthProtocol -> :md5
        :usmHMACSHAAuthProtocol -> :sha
      end

    auth_key =
      if is_nil(auth_pass) do
        []
      else
        hash_algo
        |> :snmp.passwd2localized_key(auth_pass, engine_id)
      end

    priv_key =
      if is_nil(priv_pass) do
        []
      else
        hash_algo
        |> :snmp.passwd2localized_key(priv_pass, engine_id)
        |> Enum.slice(0..15)
      end

    [ sec_name: credential.sec_name,
      auth:     auth,
      auth_key: auth_key,
      priv:     priv,
      priv_key: priv_key
    ]
  end

  defp register_usm_user(
    %{sec_model: :usm} = credential,
    engine_id
  ) do
    username = credential.sec_name
    config   =
      get_usm_user_config(credential, engine_id)

    result =
      :snmpm.register_usm_user(engine_id, username, config)

    case result do
      :ok ->
        :ok

      {:error, {:already_registered, _, _}} ->
        :ok

      {:error, reason} = error ->
        :ok = Logger.error("Unable to register USM user '#{username}': #{inspect(reason)}")

        error
    end
  end

  defp register_usm_user(_credential, _engine_id),
    do: :ok

  defp register_agent(target, uri, credential, engine_id)
  do
    netaddr   = NetAddr.ip(uri.host)
    cred_list = Map.to_list(credential)
    cred_keys =
      [ :version,
        :sec_model,
        :community,
        :sec_level,
        :sec_name
      ]

    config =
      [ engine_id: engine_id,
        address:   NetAddr.netaddr_to_list(netaddr),
        port:      uri.port || 161,
        tdomain:   get_transport_from_netaddr(netaddr)
      ] ++ Keyword.take(cred_list, cred_keys)

    :ok = Logger.debug("Will register agent #{uri} with target #{inspect(target)} and config #{inspect(config)}.")

    result =
      :snmpm.register_agent(__MODULE__, target, config)

    case result do
      :ok ->
        :ok

      {:error, {:already_registered, _}} ->
        :ok

      {:error, {:already_registered, _, _}} ->
        :ok

      {:error, reason} = error ->
        :ok = Logger.error("Unable to register agent for #{uri}: #{inspect(reason)}")

        error
    end
  end

  defp usm_stat_oid_to_name(oid) do
    case oid do
      [1,3,6,1,6,3,15,1,1,1,0] -> :usmStatsUnsupportedSecLevels
      [1,3,6,1,6,3,15,1,1,2,0] -> :usmStatsNotInTimeWindows
      [1,3,6,1,6,3,15,1,1,3,0] -> :usmStatsUnknownUserNames
      [1,3,6,1,6,3,15,1,1,4,0] -> :usmStatsUnknownEngineIDs
      [1,3,6,1,6,3,15,1,1,5,0] -> :usmStatsWrongDigests
      [1,3,6,1,6,3,15,1,1,6,0] -> :usmStatsDecryptionErrors
    end
  end

  defp groom_erl_varbind(
    %{type: t, value: v} = varbind
  ) do
    new_v =
      case t do
        :"OCTET STRING" -> :binary.list_to_bin(v)
        _               -> v
      end

    %{varbind|value: new_v}
  end

  defp groom_snmp_result(result) do
    sort_fun =
      fn {_, _, _, _, original_index} ->
        original_index
      end

    case result do
      {:ok, {reply, err_index, varbinds}, _} ->
        if {reply, err_index} == {:noError, 0} do
          result =
            varbinds
            |> Enum.sort_by(sort_fun)
            |> Enum.map(fn {_, oid, type, value, _} ->
              %{oid: oid, type: type, value: value}
              |> groom_erl_varbind
            end)

          {:ok, result}
        else
          {_, oid, type, value, _} =
            Enum.at(varbinds, err_index - 1)

          varbind =
            %{oid: oid, type: type, value: value}
            |> groom_erl_varbind

          {:error, {reply, varbind}}
        end

      {:error, {:invalid_oid, {:error, :not_found}}} ->
        :ok = Logger.error("Unknown OID")

        {:error, :unknown_oid}

      {:error, {:invalid_oid, {:ok, oid}}} ->
        oid_string = Enum.join(oid, ".")

        :ok = Logger.error("Invalid OID #{inspect(oid_string)}")

        {:error, {:invalid_oid, oid}}

      {:error, {:send_failed, _, reason}} ->
        :ok = Logger.error("Send failed: #{inspect(reason)}")

        {:error, reason}

      {:error, {:invalid_sec_info, _, snmp_info}} ->
        {_, _, [{:varbind, oid, _, _, _} | _]} = snmp_info

        name = usm_stat_oid_to_name(oid)

        :ok = Logger.error("Received USM stats response: #{name}")

        {:error, name}

      {:error, {:timeout, _}} ->
        :ok = Logger.error("Timeout!")

        {:error, :etimedout}

      other ->
        :ok = Logger.error("Unexpected result: #{inspect(other)}")

        {:error, :unknown_error}
    end
  end

  defp discover_engine_id(uri, target_name) do
    timeout =
      Application.get_env(
        :snmp_ex,
        :engine_discovery_timeout
      )

    with {:error, _} <-
           :snmpm_config.get_agent_engine_id(target_name)
    do
      DiscoveryAgent.discover_engine_id(
        uri,
        timeout: timeout
      )
    end
  end

  defp warmup_engine_boots_and_engine_time(
    %{sec_model: :usm} = _credential,
    engine_id,
    target_name
  ) do
    {:ok, engine_boots} =
      :snmpm_config.get_usm_eboots(engine_id)

    if engine_boots == 0 do
      # warm-up to update the engineBoots and engineTime in
      # SNMPM

      sync_get(target_name, [], 2000)
    end

    :ok
  end

  defp warmup_engine_boots_and_engine_time(
    _credential,
    _engine_id,
    _target_name
  ), do: :ok

  defp sha_sum(string) when is_binary(string),
    do: :crypto.hash(:sha, string)

  defp is_dotted_decimal(string)
      when is_binary(string),
    do: string =~ ~r/^\.?\d(\.\d)+$/

  defp is_dotted_decimal(_string),
    do: false

  defp normalize_to_oids([[]]),
    do: []

  defp normalize_to_oids(objects) do
    objects
    |> Enum.reduce([], fn object, acc ->
      cond do
        :snmp_misc.is_oid(object) ->
          [object|acc]

        is_dotted_decimal(object) ->
          [string_oid_to_list(object)|acc]

        is_atom(object) ->
          {:ok, oid} = resolve_object_name_to_oid(object)

          [oid|acc]

        true ->
          atom = String.to_atom(object)
          {:ok, oid} = resolve_object_name_to_oid(atom)

          [oid|acc]
      end
    end)
    |> Enum.reverse()
  end

  defp _perform_snmp_op(
    op,
    varbinds,
    target,
    context,
    timeout
  ) do
    case op do
      :get ->
        oids =
          varbinds
          |> Enum.map(& &1.oid)
          |> normalize_to_oids

        sync_get(
          target,
          oids,
          timeout,
          context
        )

      :get_next ->
        oids =
          varbinds
          |> Enum.map(& &1.oid)
          |> normalize_to_oids

        sync_get_next(
          target,
          context,
          oids,
          timeout
        )

      :set ->
        vars_and_vals =
          varbinds
          |> Enum.map(fn v ->
            if Map.has_key?(v, :type) do
              {v.oid, v.type, v.value}
            else
              {v.oid, v.value}
            end
          end)

        sync_set(target, context, vars_and_vals, timeout)
    end
  end

  def sync_get(target, oids, timeout) do
    sync_get(target, oids, timeout, "")
  end

  defp perform_snmp_op(
    op,
    varbinds,
    uri,
    credential,
    options
  ) do
    target      = generate_target_name(uri, credential)
    erl_context =
      options
      |> Keyword.get(:context, "")
      |> :binary.bin_to_list()

    discover_fun = fn ->
      with %{sec_model: :usm} <- credential,
           {:ok, eid} <- discover_engine_id(uri, target) do
        :binary.list_to_bin(eid)
      else
        _error ->
          Utility.local_engine_id()
      end
    end

    engine_id =
      options
      |> Keyword.get_lazy(:engine_id, discover_fun)
      |> :binary.bin_to_list()

    with :ok <-
           register_usm_user(credential, engine_id),
         :ok <-
           register_agent(
             target,
             uri,
             credential,
             engine_id
           ),
         :ok <-
           warmup_engine_boots_and_engine_time(
             credential,
             engine_id,
             target
           )
    do
      result =
        _perform_snmp_op(
          op,
          varbinds,
          target,
          erl_context,
          get_timeout()
        )

      groom_snmp_result(result)
    end
  end

  defp generate_target_name(uri, credential) do
    # Make a concise target name that is unique per host,
    # per credential

    "#{uri}#{inspect(credential)}"
    |> sha_sum
    |> :binary.bin_to_list()
  end

  @type object_name
    :: binary
     | atom

  @type object_id
    :: object_name
     | [non_neg_integer, ...]

  @type asn1_type  :: atom | binary
  @type asn1_value :: any
  @type credential :: map

  @type req_varbind
    :: %{oid: object_id}
     | %{oid: object_id, type: asn1_type}
     | %{oid: object_id, type: asn1_type, value: asn1_value}

  @type varbind
    :: %{oid:   object_id,
         type:  asn1_type,
         value: asn1_value,
       }

  @type req_params
    :: %{uri: URI.t,
         credential: credential,
         varbinds: [req_varbind, ...],
       }

  @type req_options :: Keyword.t

  @type request_result
    :: {:ok, [varbind, ...]}
     | {:error, any}

  @doc """
  Perform an SNMP GET/SET request.

  ## Example

      iex> %{uri: URI.parse("snmp://an-snmp-host.local"),
      ...>   credential: v2_cred,
      ...>   varbinds: [%{oid: [1,3,6,1,2,1,1,5,0]}],
      ...> } |> SNMP.request
      { :ok,
        [ %{oid: [1, 3, 6, 1, 2, 1, 1, 5, 0],
            type: :"OCTET STRING",
            value: "an-snmp-host"
          }
        ]
      }

      iex> %{uri: URI.parse("snmp://an-snmp-host.local"),
      ...>   credential: v2_cred,
      ...>   varbinds: [
      ...>     %{oid: [1,3,6,1,2,1,1,5,0],
      ...>       type: :s,
      ...>       value: "new-hostname",
      ...>     },
      ...>   ],
      ...> } |> SNMP.request
      { :ok,
        [ %{oid: [1, 3, 6, 1, 2, 1, 1, 5, 0],
            type: :"OCTET STRING",
            value: "new-hostname"
          }
        ]
      }
  """
  @spec request(req_params, req_options)
    :: request_result
  def request(
    %{uri: %{scheme: _, host: _, port: _} = uri,
      credential: credential,
      varbinds: varbinds,
    },
    options \\ []
  )   when is_list(varbinds)
       and is_list(options)
  do
    with op when not is_nil(op) <-
           ( cond do
               Enum.all?(
                 varbinds,
                 & &1[:oid] && &1[:value]
               ) ->
                 :set

               Enum.all?(
                 varbinds,
                 & &1[:oid] && (&1[:type] == :next)
               ) ->
                 :get_next

               Enum.all?(varbinds, & &1[:oid]) ->
                 :get

               true ->
                 :ok = Logger.error("Request contains unacceptable varbinds: #{inspect(varbinds)}")

                 {:error, :einval}
             end
           ),
         {:ok, ip_uri} <- resolve_host_in_uri(uri)
    do
      perform_snmp_op(
        op,
        varbinds,
        ip_uri,
        credential,
        options
      )
    end
  end

  @doc """
  Perform an SNMP walk using GETNEXT operations.

  This function returns a stream, which ensures that the
  resulting walk is bounded.

  ## Example

      iex> %{uri: URI.parse("snmp://an-snmp-host.local"),
      ...>   credential: v3_cred,
      ...>   varbinds: [%{oid: "ipAddrTable"}],
      ...> } |> SNMP.walk
      ...> |> Enum.take(1)
      [ %{oid: [1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 192, 0, 2, 1],
          type: :IpAddress,
          value: [192, 0, 2, 1],
        }
      ]
  """
  @spec walk(req_params, req_options)
    :: Enumerable.t
  def walk(
    %{uri: uri,
      credential: credential,
      varbinds: [%{oid: object}|_],
    },
    options \\ []
  ) do
    [base_oid] = normalize_to_oids([object])

    %{oid: base_oid}
    |> Stream.iterate(fn %{oid: last_oid} ->
      %{uri: uri,
        credential: credential,
        varbinds: [%{oid: last_oid, type: :next}]
      }
      |> request(options)
      |> elem(1)
      |> List.first
    end)
    |> Stream.take_while(fn %{oid: oid} ->
      List.starts_with?(oid, base_oid)
    end)
    |> Stream.drop(1)
  end

  @doc """
  Perform an SNMP bulkwalk using GETBULK operations.

  This function returns a stream that uses GETBULK for more efficient retrieval
  of SNMP table data compared to regular walk operations.

  ## Example

      iex> %{uri: URI.parse("snmp://an-snmp-host.local"),
      ...>   credential: v2_cred,
      ...>   varbinds: [%{oid: "ifTable"}],
      ...> } |> SNMP.bulkwalk(max_repetitions: 10)
      ...> |> Enum.take(5)
      [ %{...}, %{...}, %{...}, %{...}, %{...} ]
  """
  @spec bulkwalk(req_params, req_options)
    :: Enumerable.t
  def bulkwalk(
    %{uri: uri,
      credential: credential,
      varbinds: [%{oid: object}|_],
    },
    options \\ []
  ) do
    # Only use bulkwalk for v2 and v3
    case credential do
      %CommunityCredential{version: :v1} ->
        # Fallback to regular walk for v1
        walk(%{uri: uri, credential: credential, varbinds: [%{oid: object}]}, options)

    _ ->
      # Use GETBULK for v2c and v3
      [base_oid] = normalize_to_oids([object])
      max_repetitions = Keyword.get(options, :max_repetitions, get_max_repetitions())
      non_repeaters = Keyword.get(options, :non_repeaters, 0)
      # debug = Keyword.get(options, :debug, false)

      # Stream implementation
      Stream.resource(
        # Initial state with loop detection
        fn -> {[base_oid], [], false, MapSet.new()} end,

        # Process function
        fn
          # End of walk reached
          {_, _, true, _} ->
            {:halt, nil}

          # We have pending results to emit
          {next_oids, [result | rest], end_reached, seen_oids} ->
            Logger.debug("Emitting result: #{inspect(result.oid)}")
            {[result], {next_oids, rest, end_reached, seen_oids}}

          # We need to fetch more results
          {[_|_] = oids_to_request, [], false, seen_oids} ->
            Logger.debug("Fetching batch with OIDs: #{inspect(oids_to_request)}")

            case bulkwalk_get_next_batch(uri, credential, oids_to_request, non_repeaters, max_repetitions, base_oid, options) do
              {:ok, results, next_oids, end_reached} ->
                if Enum.empty?(results) do
                  Logger.debug("No results in subtree, ending walk")
                  {:halt, nil}
                else
                  # Check if we've already seen these OIDs (loop detection)
                  new_oid_set = MapSet.new(results, & &1.oid)

                  # Check if all new OIDs are already seen (loop detection)
                  loop_detected = MapSet.subset?(new_oid_set, seen_oids) && !Enum.empty?(new_oid_set)

                  if loop_detected do
                    Logger.debug("Loop detected - all received OIDs have been seen before")
                    {:halt, nil}
                  else
                    # Update seen OIDs with the new results
                    updated_seen = MapSet.union(seen_oids, new_oid_set)

                    # Continue the walk with these results
                    [first | rest] = results
                    {[first], {next_oids, rest, end_reached, updated_seen}}
                  end
                end

              {:error, reason} ->
                Logger.debug("Error in bulkwalk: #{inspect(reason)}")
                {:halt, nil}
            end

          # No more OIDs to request
          {[], [], _, _} ->
            Logger.debug("No more OIDs to request, ending walk")
            {:halt, nil}
        end,

        # Cleanup function
        fn _ -> nil end
      )
  end
end

# Helper function to get the next batch for bulkwalk
defp bulkwalk_get_next_batch(uri, credential, oids, non_repeaters, max_repetitions, base_oid, options) do
  debug = Keyword.get(options, :debug, false)

  case bulkwalk_perform_request(uri, credential, oids, non_repeaters, max_repetitions, options) do
    {:ok, varbinds} ->
      # Filter out endOfMibView entries and check if end was reached
      {regular_varbinds, end_of_view_reached} = bulkwalk_filter_results(varbinds, oids, debug)

      # Filter to only OIDs in the subtree
      in_subtree = Enum.filter(regular_varbinds, fn %{oid: oid} ->
        result = List.starts_with?(oid, base_oid)
        if !result do
          Logger.debug ("OID #{inspect(oid)} is outside the requested subtree #{inspect(base_oid)}")
          Logger.debug("OID #{inspect(oid)} is outside the requested subtree #{inspect(base_oid)}")
        end

        result
      end)

      Logger.debug("Got #{length(in_subtree)} results in subtree out of #{length(varbinds)} total")

      # Determine next OIDs to request
      next_oids =
        cond do
          # If we've reached the end of MIB view, stop here
          end_of_view_reached ->
            Logger.debug("EndOfMibView reached, no more OIDs to request")
            []

          # If we have no results in the subtree, stop here
          Enum.empty?(in_subtree) ->
            Logger.debug("No results in subtree, no more OIDs to request")
            []

          # Otherwise, continue with the next OID
          true ->
            # Get the lexicographically greatest OID for the next request
            [bulkwalk_get_next_oid(in_subtree)]
        end

      # Double check - if we're using a very broad OID like [1,3,6]
      # we need to be more aggressive about stopping
      broad_oid_check =
        if is_list(base_oid) && length(base_oid) <= 3 &&
           !Enum.empty?(regular_varbinds) do
          # Get all endOfMibView markers
          {_, end_of_mib_markers} = Enum.split_with(varbinds, fn %{type: type} ->
            type != :"END OF MIB VIEW" && type != :endOfMibView
          end)

          # For broad OIDs, even one endOfMibView marker might indicate we're at the end
          if !Enum.empty?(end_of_mib_markers) do
            Logger.debug("Broad OID detected with endOfMibView markers - extra check enabled")
            true
          else
            false
          end
        else
          false
        end

      end_reached = end_of_view_reached || Enum.empty?(next_oids) || broad_oid_check

      Logger.debug("Next OIDs to request: #{inspect(next_oids)}")
      Logger.debug("End reached: #{end_reached}")

      {:ok, in_subtree, next_oids, end_reached}

    {:error, reason} ->
      Logger.debug("Error in bulkwalk request: #{inspect(reason)}")
      {:error, reason}
  end
end

# Helper function to perform the actual bulk request
defp bulkwalk_perform_request(uri, credential, oids, non_repeaters, max_repetitions, options) do
  _perform_bulk_op(uri, credential, oids, non_repeaters, max_repetitions, options)
end

# Helper function to filter out endOfMibView results and detect if end is reached
defp bulkwalk_filter_results(varbinds, requested_oids, debug) do
  # Split into regular varbinds and endOfMibView markers
  {regular_varbinds, end_of_mib_markers} = Enum.split_with(varbinds, fn %{type: type} ->
    type != :"END OF MIB VIEW" && type != :endOfMibView
  end)

  Logger.debug("Total varbinds: #{length(varbinds)}")
  Logger.debug("Regular varbinds: #{length(regular_varbinds)}")
  Logger.debug("EndOfMibView markers: #{length(end_of_mib_markers)}")

  if !Enum.empty?(end_of_mib_markers) do
    Enum.each(end_of_mib_markers, fn %{oid: oid} ->
      Logger.debug("  EndOfMibView marker for OID: #{inspect(oid)}")
    end)
  end

  # For very broad OIDs we need more aggressive detection
  is_broad_requested_oid = Enum.any?(requested_oids, fn oid -> length(oid) <= 3 end)

  # Check if any requested OIDs have reached endOfMibView
  end_of_view_reached =
    if Enum.empty?(end_of_mib_markers) do
      false
    else
      # If we're walking a very broad OID like [1,3,6], even one endOfMibView might be significant
      if is_broad_requested_oid && length(end_of_mib_markers) > 0 do
        if debug do
          Logger.debug ("Broad OID detected with endOfMibView markers - treating as end of view")
        end
        true
      else
        # For normal OIDs, we check if any requested OID has an endOfMibView marker
        has_end_markers = Enum.any?(requested_oids, fn req_oid ->
          Enum.any?(end_of_mib_markers, fn %{oid: oid} ->
            # Check if this endOfMibView marker is for this requested OID
            # The marker OID should start with the requested OID
            result = List.starts_with?(oid, req_oid)
            if debug && result do
              Logger.debug ("  Found endOfMibView marker #{inspect(oid)} for requested OID #{inspect(req_oid)}")
            end
            result
          end)
        end)

        if debug, do: Logger.debug ("Has end markers: #{has_end_markers}")
        has_end_markers
      end
    end

  if debug do
    Logger.debug ("End of view reached: #{end_of_view_reached}")
  end

  {regular_varbinds, end_of_view_reached}
end

# Helper function to get the next OID for continuation
defp bulkwalk_get_next_oid(results) do
  results
  |> Enum.sort_by(& &1.oid)
  |> List.last()
  |> Map.get(:oid)
end

# Add this function to support get_max_repetitions
defp get_max_repetitions,
  do: Application.get_env(:snmp_ex, :max_repetitions, 10)

  @type mib_name :: String.t()

  @spec load_mib(mib_name)
    :: :ok
     | {:error, term}
  def load_mib(mib_name)
      when is_binary(mib_name)
  do
    erl_mib_name = :binary.bin_to_list(mib_name)

    case :snmpm.load_mib(erl_mib_name) do
      :ok ->
        :ok

      {:error, reason} = error ->
        :ok = Logger.error("Unable to load MIB #{inspect(mib_name)}: #{reason}")

        error
    end
  end

  @spec resolve_object_name_to_oid(object_id)
    :: {:ok, object_id}
     | {:error, term}
     | no_return
  def resolve_object_name_to_oid(oid)
      when is_list(oid),
    do: oid

  def resolve_object_name_to_oid(name)
      when is_atom(name)
  do
    try do
      with {:ok, [oid]} <- :snmpm.name_to_oid(name),
        do: {:ok, oid}
    rescue
      e in ArgumentError ->
        :ok = Logger.warning("Unhandled exception: did you forget to `SNMP.start`?")

        reraise(e, __STACKTRACE__)
    end
  end

  @doc """
  Returns a keyword list containing the given SNMP
  credentials.

  ## Example

      iex> SNMP.credential(%{community: "public"})
      %SNMP.CommunityCredential{version: :v1, sec_model: :v1, community: ~c"public"}

      iex> SNMP.credential(
      ...>   %{version: :v2, community: "public"}
      ...> )
      %SNMP.CommunityCredential{version: :v2, sec_model: :v2c, community: ~c"public"}

      iex> SNMP.credential(%{sec_name: "user"})
      %SNMP.USMCredential{
        version: :v3,
        sec_model: :usm,
        sec_level: :noAuthNoPriv,
        sec_name: ~c"user",
        auth: :usmNoAuthProtocol,
        auth_pass: nil,
        priv: :usmNoPrivProtocol,
        priv_pass: nil
      }


      iex> SNMP.credential(
      ...>   %{sec_name: "user",
      ...>     auth: :sha,
      ...>     auth_pass: "authpass",
      ...>   }
      ...> )
      %SNMP.USMCredential{
        version: :v3,
        sec_model: :usm,
        sec_level: :authNoPriv,
        sec_name: ~c"user",
        auth: :usmHMACSHAAuthProtocol,
        auth_pass: ~c"authpass",
        priv: :usmNoPrivProtocol,
        priv_pass: nil
      }


      iex> SNMP.credential(
      ...>   %{sec_name: "user",
      ...>     auth: :sha,
      ...>     auth_pass: "authpass",
      ...>     priv: :aes,
      ...>     priv_pass: "privpass",
      ...>   }
      ...> )
      %SNMP.USMCredential{
        version: :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name: ~c"user",
        auth: :usmHMACSHAAuthProtocol,
        auth_pass: ~c"authpass",
        priv: :usmAesCfb128Protocol,
        priv_pass: ~c"privpass"
      }

  """
  def credential(
    %{version: :v2,
      community: community,
    }
  )   when is_binary(community)
  do
    %CommunityCredential{
      version: :v2,
      sec_model: :v2c,
      community: :binary.bin_to_list(community),
    }
  end

  def credential(%{community: community})
      when is_binary(community)
  do
    %CommunityCredential{
      version: :v1,
      sec_model: :v1,
      community: :binary.bin_to_list(community),
    }
  end

  def credential(
    %{sec_name: sec_name,
      auth: auth,
      auth_pass: auth_pass,
      priv: priv,
      priv_pass: priv_pass,
    }
  )   when is_binary(sec_name)
       and auth in [:md5, :sha]
       and is_binary(auth_pass)
       and priv in [:des, :aes]
       and is_binary(priv_pass)
  do
    %USMCredential{
      sec_level: :authPriv,
      sec_name: :binary.bin_to_list(sec_name),
      auth: auth_proto_to_snmpm_auth(auth),
      auth_pass: :binary.bin_to_list(auth_pass),
      priv: priv_proto_to_snmpm_priv(priv),
      priv_pass: :binary.bin_to_list(priv_pass),
    }
  end

  def credential(
    %{sec_name: sec_name,
      auth: auth,
      auth_pass: auth_pass,
    }
  )   when is_binary(sec_name)
       and auth in [:md5, :sha]
       and is_binary(auth_pass)
  do
    %USMCredential{
      sec_level: :authNoPriv,
      sec_name: :binary.bin_to_list(sec_name),
      auth: auth_proto_to_snmpm_auth(auth),
      auth_pass: :binary.bin_to_list(auth_pass),
    }
  end

  def credential(%{sec_name: sec_name})
      when is_binary(sec_name)
  do
    %USMCredential{
      sec_name: :binary.bin_to_list(sec_name),
    }
  end

  defp auth_proto_to_snmpm_auth(:md5), do: :usmHMACMD5AuthProtocol
  defp auth_proto_to_snmpm_auth(:sha), do: :usmHMACSHAAuthProtocol

  defp priv_proto_to_snmpm_priv(:des), do: :usmDESPrivProtocol
  defp priv_proto_to_snmpm_priv(:aes), do: :usmAesCfb128Protocol

  @doc """
  Converts `oid` to dot-delimited string.

  ## Example

      iex> SNMP.list_oid_to_string([1,3,6,1,2,1,1,5,0])
      "1.3.6.1.2.1.1.5.0"

  """
  @spec list_oid_to_string([non_neg_integer])
    :: String.t()
     | no_return
  def list_oid_to_string(oid)
      when is_list(oid),
    do: Enum.join(oid, ".")

  @doc """
  Converts dot-delimited `oid` string to list.

  ## Example

      iex> SNMP.string_oid_to_list("1.3.6.1.2.1.1.5.0")
      [1,3,6,1,2,1,1,5,0]

  """
  @spec string_oid_to_list(String.t())
    :: [non_neg_integer]
     | no_return
  def string_oid_to_list(oid)
      when is_binary(oid)
  do
    oid
    |> String.split(".", trim: true)
    |> Enum.map(&String.to_integer/1)
  end

  defp _perform_bulk_op(uri, credential, oids, non_repeaters, max_repetitions, options) do
    log_operations? = Application.get_env(:snmp_ex, :log_snmp_operations, false)

    if log_operations? do
      Logger.debug("SNMP perform_bulk_op:")
      Logger.debug("  OIDs: #{inspect(oids)}")
      Logger.debug("  Non-repeaters: #{non_repeaters}")
      Logger.debug("  Max-repetitions: #{max_repetitions}")
    end

    target = generate_target_name(uri, credential)
    erl_context =
      options
      |> Keyword.get(:context, "")
      |> :binary.bin_to_list()

    discover_fun = fn ->
      with %{sec_model: :usm} <- credential,
           {:ok, eid} <- discover_engine_id(uri, target) do
        :binary.list_to_bin(eid)
      else
        _error ->
          Utility.local_engine_id()
      end
    end

    engine_id =
      options
      |> Keyword.get_lazy(:engine_id, discover_fun)
      |> :binary.bin_to_list()

    result = with :ok <-
           register_usm_user(credential, engine_id),
         :ok <-
           register_agent(
             target,
             uri,
             credential,
             engine_id
           ),
         :ok <-
           warmup_engine_boots_and_engine_time(
             credential,
             engine_id,
             target
           )
    do
      sync_get_bulk(
        target,
        non_repeaters,
        max_repetitions,
        oids,
        get_timeout(),
        erl_context
      )
    end

    case result do
      {:error, {:invalid_oid, _}} = error ->
        if log_operations?, do: Logger.debug("SNMP: Invalid OID detected in request: #{inspect(error)}")
        # Return empty result to allow the walk to continue with other OIDs
        {:ok, []}

      {:error, {:send_failed, _, :tooBig}} = error ->
        # Handle tooBig error - this means we're requesting too much data at once
        if log_operations?, do: Logger.debug("SNMP: tooBig error received: #{inspect(error)}")
        if max_repetitions > 1 do
          # Try again with half the max_repetitions
          new_max_rep = div(max_repetitions, 2)
          if log_operations?, do: Logger.debug("SNMP: Retrying with max_repetitions = #{new_max_rep}")
          _perform_bulk_op(uri, credential, oids, non_repeaters, new_max_rep, options)
        else
          # If max_repetitions is already 1, we can't reduce further
          {:error, :tooBig}
        end

      _ ->
        groom_snmp_result(result)
    end
  end
end
