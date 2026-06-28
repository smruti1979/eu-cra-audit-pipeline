from langgraph.graph import StateGraph, START, END
from schemas import ComplianceState
from agents import sbom_generator_agent, vulnerability_scanner_agent, compliance_officer_agent

def create_compliance_graph():
    """Assembles and compiles the multi-agent execution pipeline graph."""
    builder = StateGraph(ComplianceState)
    
    # Register Node operations
    builder.add_node("sbom_generator", sbom_generator_agent)
    builder.add_node("vulnerability_scanner", vulnerability_scanner_agent)
    builder.add_node("compliance_officer", compliance_officer_agent)

    # Form logical graph path
    builder.add_edge(START, "sbom_generator")
    builder.add_edge("sbom_generator", "vulnerability_scanner")
    builder.add_edge("vulnerability_scanner", "compliance_officer")
    builder.add_edge("compliance_officer", END)

    return builder.compile()

# Instantiated single global workflow engine
compliance_pipeline = create_compliance_graph()
