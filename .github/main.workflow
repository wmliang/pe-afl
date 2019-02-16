workflow "on push" {
  on = "push"
  resolves = ["Python Syntax Checker"]
}

action "Python Syntax Checker" {
  uses = "wmliang/pe-afl/.github/Python_Syntax_Checker@Github-Action"
}
