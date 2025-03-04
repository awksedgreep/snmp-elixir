defmodule SNMP.Utility.Test do
  use ExUnit.Case

  import SNMP.Utility

  # Takes a strict poset, here represented as a Hasse diagram,
  #
  #       a   d
  #      / \ /
  #     b   c    e
  #
  # to
  #
  #     [[b, c, e], [a, d]]
  #
  test "Partitions a strict poset as maximal antichains of minimal elements" do
    adjacencies = %{:e => [], :b => [:d, :a], :c => [:a]}

    result = topological_sort(adjacencies)
    expected = [
      [:c, :b, :e],
      [:a, :d]
    ]

    # Test that we have the same number of levels
    assert length(result) == length(expected)

    # Test that each level contains the same elements (regardless of order)
    Enum.zip(result, expected) |> Enum.each(fn {result_level, expected_level} ->
      assert MapSet.new(result_level) == MapSet.new(expected_level),
        "Expected #{inspect(expected_level)} but got #{inspect(result_level)}"
    end)
  end

  # Raises on
  #
  #     :a<----:c
  #       \     ^
  #        \    |
  #         '->:b
  #
  test "Raises when a cycle is detected" do
    adjacencies = %{:a => [:c], :b => [:a], :c => [:b]}

    # Capture the actual error to inspect it
    error = assert_raise RuntimeError, fn ->
      topological_sort(adjacencies)
    end

    # Verify error message starts with expected text
    assert String.starts_with?(error.message, "detected cycle in subset: ")

    # Extract the cycle members from the error message
    cycle_str = String.replace(error.message, "detected cycle in subset: ", "")
    cycle_members = Code.eval_string(cycle_str) |> elem(0)

    # Verify all expected elements are in the cycle (regardless of order)
    expected_members = [:a, :b, :c]
    assert Enum.sort(cycle_members) == Enum.sort(expected_members)
  end
end
