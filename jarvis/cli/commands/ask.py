"""Ask JARVIS about its local findings, with an optional offline model."""

from jarvis.response import assistant
from jarvis.service.schedule import JOBS


def cmd_ask(args, store):
    result = assistant.answer(store, " ".join(args.question), jobs=JOBS)
    print(result["answer"])
    if result["source"] == "ollama":
        print("\n[offline Ollama synthesis; no action was taken]")
    return 0


def add_parser(sub):
    p = sub.add_parser("ask", help="ask about current findings; open questions use local Ollama")
    p.add_argument("question", nargs="+", help="question to answer")
    p.set_defaults(fn=lambda args, store: cmd_ask(args, store))
    return p
