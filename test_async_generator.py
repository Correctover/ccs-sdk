"""
Test async_govern and generator_govern decorators
"""
import asyncio
import sys
sys.path.insert(0, '/tmp/ccs-sdk')

from ccs import async_govern, generator_govern, CCSConfig, GovernanceResult


async def test_async_govern_allow():
    """Test async_govern allows execution when policy allows"""
    
    @async_govern(policy="default")
    async def async_tool(message: str) -> str:
        await asyncio.sleep(0.01)  # Simulate async work
        return f"Processed: {message}"
    
    result = await async_tool("hello")
    assert result == "Processed: hello"
    print("✅ async_govern ALLOW test passed")


async def test_async_govern_deny():
    """Test async_govern blocks execution when policy denies"""
    
    # Create a custom policy that denies everything
    from ccs import CCSPolicy
    
    class DenyAllPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            return GovernanceResult.DENY
    
    from ccs import get_runtime
    runtime = get_runtime()
    runtime.register_policy("deny_all", DenyAllPolicy())
    
    @async_govern(policy="deny_all")
    async def async_tool(message: str) -> str:
        return f"Should not execute: {message}"
    
    try:
        await async_tool("hello")
        assert False, "Should have raised PermissionError"
    except PermissionError as e:
        assert "CCS governance DENIED async tool" in str(e)
        print("✅ async_govern DENY test passed")


def test_generator_govern_allow():
    """Test generator_govern allows iteration when policy allows"""
    
    @generator_govern(policy="default")
    def stream_tool(count: int):
        for i in range(count):
            yield f"chunk_{i}"
    
    results = list(stream_tool(3))
    assert results == ["chunk_0", "chunk_1", "chunk_2"]
    print("✅ generator_govern ALLOW test passed")


def test_generator_govern_deny():
    """Test generator_govern blocks iteration when policy denies"""
    
    from ccs import CCSPolicy, get_runtime
    
    class DenyAllPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            return GovernanceResult.DENY
    
    runtime = get_runtime()
    runtime.register_policy("deny_all_gen", DenyAllPolicy())
    
    @generator_govern(policy="deny_all_gen")
    def stream_tool(count: int):
        for i in range(count):
            yield f"chunk_{i}"
    
    try:
        list(stream_tool(3))
        assert False, "Should have raised PermissionError"
    except PermissionError as e:
        assert "CCS governance DENIED generator" in str(e)
        print("✅ generator_govern DENY test passed")


async def main():
    print("Testing CCS v1.1 async and generator support...\n")
    
    # Test async
    await test_async_govern_allow()
    await test_async_govern_deny()
    
    # Test generator
    test_generator_govern_allow()
    test_generator_govern_deny()
    
    print("\n✅ All tests passed! CCS v1.1 supports sync, async, and generator tools.")


if __name__ == "__main__":
    asyncio.run(main())
