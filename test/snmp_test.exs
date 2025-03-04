defmodule SNMP.Test do
  use ExUnit.Case, async: false
  doctest SNMP, except: [request: 2, walk: 2, bulkwalk: 2]

  # For a full explanation of magic values, please see
  # http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html

  @moduletag :integrated

  @sysname_oid [1, 3, 6, 1, 2, 1, 1, 5, 0]
  @sysname_result %{
    oid: @sysname_oid,
    type: :"OCTET STRING",
    value: "test-52567"
  }

  # docker pull davaeron/snmpsim
  # docker run -d -p 161:161/udp davaeron/snmpsim
  # required for integration tests
  @working_agent "localhost"

  # Optimistically, should be a broken agent
  @borking_agent "localhost:65535"

  # Check if we are using CI
  # if we are in CI, we use container alias for hostname
  defp get_working_agent() do
    if System.get_env("CI_SERVER") == "yes" do
      "snmpsim"
    else
      @working_agent
    end
  end

  defp get_credential(:none, :none),
    do: SNMP.credential(%{sec_name: "usr-none-none"})

  defp get_credential(auth, :none)
      when auth in [:md5, :sha]
  do
    %{sec_name: "usr-#{auth}-none",
      auth: auth,
      auth_pass: "authkey1",
    }
    |> SNMP.credential
  end

  defp get_credential(auth, priv)
      when auth in [:md5, :sha]
       and priv in [:des]
  do
    %{sec_name: "usr-#{auth}-#{priv}",
      auth: auth,
      auth_pass: "authkey1",
      priv: priv,
      priv_pass: "privkey1"
    }
    |> SNMP.credential
  end

  defp get_sysname_with_engine_id(credential, agent) do
    get_sysname(
      credential,
      agent,
      engine_id: <<0x80004fb805636c6f75644dab22cd::14*8>>
    )
  end

  defp get_sysname(credential, agent, opts \\ []) do
    %{uri: URI.parse("snmp://#{agent}"),
      credential: credential,
      varbinds: [%{oid: @sysname_oid}],
    }
    |> SNMP.request(opts)
  end

  test "Hostname resolution breaks gracefully" do
    hostname = "x80004fb805636c6f75644dab22cc.local"

    result =
      :none
      |> get_credential(:none)
      |> get_sysname_with_engine_id(hostname)

    assert result == {:error, :nxdomain}
  end

  describe "v3 GET noAuthNoPriv" do
    test "get without engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname_with_engine_id(get_working_agent())

      assert result == {:ok, [@sysname_result]}
    end

    test "timeout without engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname_with_engine_id(@borking_agent)

      assert result == {:error, :etimedout}
    end

    test "get with engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname(get_working_agent())

      assert result == {:ok, [@sysname_result]}
    end

    test "timeout with engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname(@borking_agent)

      assert result == {:error, :etimedout}
    end
  end

  describe "v3 get authNoPriv" do
    test "get without engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname_with_engine_id(get_working_agent())

        assert result == {:ok, [@sysname_result]}
      end
    end

    test "timeout without engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname_with_engine_id(@borking_agent)

        assert result == {:error, :etimedout}
      end
    end

    test "get with engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname(get_working_agent())

        assert result == {:ok, [@sysname_result]}
      end
    end

    test "timeout with engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname(@borking_agent)

        assert result == {:error, :etimedout}
      end
    end
  end

  describe "v3 get authPriv" do
    test "get without engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des]
      do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname_with_engine_id(get_working_agent())

        assert result == {:ok, [@sysname_result]}
      end
    end

    test "timeout without engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des]
      do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname_with_engine_id(@borking_agent)

        assert result == {:error, :etimedout}
      end
    end

    test "get with engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des]
      do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname(get_working_agent())

        assert result == {:ok, [@sysname_result]}
      end
    end

    test "timeout with engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des]
      do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname(@borking_agent)

        assert result == {:error, :etimedout}
      end
    end
  end

  describe "v1" do
    test "set" do
      req =
        %{uri: URI.parse("snmp://#{get_working_agent()}"),
          credential: SNMP.credential(%{community: "public"}),
          varbinds: [%{oid: @sysname_oid}],
        }

      {:ok, [%{value: v}]} = before = SNMP.request(req)

      {_, _, us} = :erlang.timestamp()

      new_v = "test-#{us}"

      %{req |
        varbinds: [
          %{oid: @sysname_oid, type: :s, value: new_v}
        ],
      }
      |> SNMP.request

      refute before == SNMP.request(req)

      %{req |
        varbinds: [
          %{oid: @sysname_oid, type: :s, value: v}
        ],
      }
      |> SNMP.request
    end
  end

  describe "v2" do
    test "set" do
      req =
        %{uri: URI.parse("snmp://#{get_working_agent()}"),
          credential: SNMP.credential(
            %{version: :v2, community: "public"}
          ),
          varbinds: [%{oid: @sysname_oid}],
        }

      {:ok, [%{value: v}]} = before = SNMP.request(req)

      {_, _, us} = :erlang.timestamp()

      new_v = "test-#{us}"

      %{req |
        varbinds: [%{oid: @sysname_oid, type: :s, value: new_v}],
      }
      |> SNMP.request

      refute before == SNMP.request(req)

      %{req |
        varbinds: [
          %{oid: @sysname_oid, type: :s, value: v}
        ],
      }
      |> SNMP.request
    end
  end

  describe "bulkwalk" do
    setup do
      uri = URI.parse("snmp://127.0.0.1")
      credential = SNMP.credential(%{version: :v2, community: "public"})
      base_oid = [1, 3, 6, 1, 2, 1, 1]  # system MIB

      {:ok, %{uri: uri, credential: credential, base_oid: base_oid}}
    end

    test "falls back to walk for v1 credentials", %{uri: uri, base_oid: base_oid} do
      v1_credential = SNMP.credential(%{community: "public"})
      req = %{
        uri: uri,
        credential: v1_credential,
        varbinds: [%{oid: base_oid}]
      }

      # When using v1, bulkwalk should return a Stream that uses walk
      stream = SNMP.bulkwalk(req)
      assert is_struct(stream, Stream)
    end

    test "respects max_repetitions option", %{uri: uri, credential: credential, base_oid: base_oid} do
      req = %{
        uri: uri,
        credential: credential,
        varbinds: [%{oid: base_oid}]
      }

      # Default max_repetitions
      stream1 = SNMP.bulkwalk(req)
      assert Enumerable.impl_for(stream1) != nil, "Expected stream1 to be enumerable"

      # Custom max_repetitions
      stream2 = SNMP.bulkwalk(req, max_repetitions: 20)
      assert Enumerable.impl_for(stream2) != nil, "Expected stream2 to be enumerable"

      # Verify the streams are different
      refute stream1 == stream2, "Expected different streams for different max_repetitions"
    end

    # test "handles invalid OID format", %{uri: uri, credential: credential} do
    #   # Test with string OID
    #   string_req = %{
    #     uri: uri,
    #     credential: credential,
    #     varbinds: [%{oid: "1.3.6.1"}]  # String OID format
    #   }
    #   assert_raise ArgumentError, ~r/Invalid OID format/, fn ->
    #     SNMP.bulkwalk(string_req)
    #   end

    #   # Test with completely invalid OID
    #   invalid_req = %{
    #     uri: uri,
    #     credential: credential,
    #     varbinds: [%{oid: "invalid"}]
    #   }
    #   assert_raise ArgumentError, ~r/Invalid OID format/, fn ->
    #     SNMP.bulkwalk(invalid_req)
    #   end

    #   # Test with wrong type
    #   wrong_type_req = %{
    #     uri: uri,
    #     credential: credential,
    #     varbinds: [%{oid: %{}}]  # Wrong type
    #   }
    #   assert_raise ArgumentError, ~r/Invalid OID format/, fn ->
    #     SNMP.bulkwalk(wrong_type_req)
    #   end
    # end

    test "validates required request parameters" do
      # Missing URI
      assert_raise KeyError, fn ->
        SNMP.bulkwalk(%{
          credential: SNMP.credential(%{version: :v2, community: "public"}),
          varbinds: [%{oid: [1, 3, 6]}]
        })
      end

      # Missing credential
      assert_raise KeyError, fn ->
        SNMP.bulkwalk(%{
          uri: URI.parse("snmp://localhost"),
          varbinds: [%{oid: [1, 3, 6]}]
        })
      end

      # Missing varbinds
      assert_raise KeyError, fn ->
        SNMP.bulkwalk(%{
          uri: URI.parse("snmp://localhost"),
          credential: SNMP.credential(%{version: :v2, community: "public"})
        })
      end
    end

    test "validates non_repeaters option", %{uri: uri, credential: credential, base_oid: base_oid} do
      req = %{
        uri: uri,
        credential: credential,
        varbinds: [%{oid: base_oid}]
      }

      # Negative non_repeaters should raise
      assert_raise ArgumentError, fn ->
        SNMP.bulkwalk(req, non_repeaters: -1)
      end

      # Zero non_repeaters should work
      stream = SNMP.bulkwalk(req, non_repeaters: 0)
      assert is_struct(stream, Stream)

      # Positive non_repeaters should work
      stream = SNMP.bulkwalk(req, non_repeaters: 1)
      assert is_struct(stream, Stream)
    end

    test "validates max_repetitions option", %{uri: uri, credential: credential, base_oid: base_oid} do
      req = %{
        uri: uri,
        credential: credential,
        varbinds: [%{oid: base_oid}]
      }

      # Negative max_repetitions should raise
      assert_raise ArgumentError, fn ->
        SNMP.bulkwalk(req, max_repetitions: -1)
      end

      # Zero max_repetitions should raise
      assert_raise ArgumentError, fn ->
        SNMP.bulkwalk(req, max_repetitions: 0)
      end

      # Positive max_repetitions should work
      stream = SNMP.bulkwalk(req, max_repetitions: 1)
      assert is_struct(stream, Stream)
    end
  end
end
