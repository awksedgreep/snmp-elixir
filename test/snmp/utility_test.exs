defmodule SNMP.Utility.Test do
  use ExUnit.Case, async: true

  alias SNMP.Utility

  describe "cycle detection" do
    test "Raises when a cycle is detected" do
      assert_raise RuntimeError, ~r/detected cycle in subset: \[:a\]/, fn ->
        Utility.detect_cycle([:a, :b, :c, :a])
      end
    end
  end
end
