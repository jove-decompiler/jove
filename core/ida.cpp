#include "ida.h"
#include "util.h"

#include <boost/algorithm/string.hpp>
#include <boost/bind/bind.hpp>
#include <boost/phoenix.hpp>
#include <boost/range/algorithm/count.hpp>
#include <boost/ref.hpp>
#include <boost/spirit/include/lex_lexertl.hpp>
#include <boost/spirit/include/qi.hpp>

#include <fstream>
#include <stdexcept>
#include <iostream>

namespace lex = boost::spirit::lex;

namespace jove {

enum token_id {
  ID_GRAPH = 1000,
  ID_TITLE,
  ID_MANHATTAN_EDGES,
  ID_LAYOUTALGORITHM,
  ID_FINETUNING,
  ID_LAYOUT_DOWNFACTOR,
  ID_LAYOUT_UPFACTOR,
  ID_LAYOUT_NEARFACTOR,
  ID_XLSPACE,
  ID_YSPACE,
  ID_COLORENTRY,
  ID_NODE,
  ID_LABEL,
  ID_EDGE,
  ID_SOURCENAME,
  ID_TARGETNAME,
  ID_COLOR,
  ID_COLON,
  ID_LEFT_BRACE,
  ID_RIGHT_BRACE,
  ID_VERTICAL_ORDER,
  ID_STR_CONST,
  ID_INT_CONST,
  ID_COMMENT,
  ID_YES,
  ID_NO,
  ID_MINDEPTH,
  ID_WHITESPACE,
  ID_EOL,
  ID_COLOR_RED,
  ID_COLOR_DARKGREEN
};

template <typename Lexer>
struct gdl_tokens : lex::lexer<Lexer>
{
  gdl_tokens()
  {
    this->self.add
        ("\"//\"[^\n]*",      ID_COMMENT)
        ("\\\"[^\"]*\\\"",    ID_STR_CONST)
        ("[0-9]+",            ID_INT_CONST)

        ("yes",               ID_YES)
        ("no",                ID_NO)

        ("red",               ID_COLOR_RED)
        ("darkgreen",         ID_COLOR_DARKGREEN)

        ("mindepth",          ID_MINDEPTH)

        ("graph",             ID_GRAPH)
        ("title",             ID_TITLE)

        ("manhattan_edges",   ID_MANHATTAN_EDGES)
        ("layoutalgorithm",   ID_LAYOUTALGORITHM)
        ("finetuning",        ID_FINETUNING)
        ("layout_downfactor", ID_LAYOUT_DOWNFACTOR)
        ("layout_upfactor",   ID_LAYOUT_UPFACTOR)
        ("layout_nearfactor", ID_LAYOUT_NEARFACTOR)
        ("xlspace",           ID_XLSPACE)
        ("yspace",            ID_YSPACE)
        ("colorentry",        ID_COLORENTRY)

        ("node",              ID_NODE)
        ("label",             ID_LABEL)
        ("edge",              ID_EDGE)
        ("sourcename",        ID_SOURCENAME)
        ("targetname",        ID_TARGETNAME)
        ("color",             ID_COLOR)
        ("vertical_order",    ID_VERTICAL_ORDER)

        ("\":\"",             ID_COLON)
        ("\"{\"",             ID_LEFT_BRACE)
        ("\"}\"",             ID_RIGHT_BRACE)

        ("\n",                ID_EOL)
        ("[ \t]+",            ID_WHITESPACE)
    ;
  }
};

struct token_info_t {
  enum token_id id;

  struct {
    std::string text;
  } _str_const;

  struct {
    int num;
  } _int_const;
};

struct on_token {
  typedef bool result_type;

  template <typename Token>
  bool operator()(Token const &t, std::list<token_info_t> &tokl) const {
    if (t.id() != ID_WHITESPACE) {
      token_info_t &toki = tokl.emplace_back();
      toki.id = (enum token_id)t.id();

      switch (t.id()) {
        case ID_INT_CONST: {
          std::string s(t.value().begin(), t.value().end());
          toki._int_const.num = strtol(s.c_str(), nullptr, 10);
          break;
        }
        case ID_STR_CONST: {
          std::string s(t.value().begin(), t.value().end());
          toki._str_const.text = s.substr(1, s.size() - 2);
          break;
        }
      }
    }

    return true; // always continue to tokenize
  }
};

bool ReadIDAFlowgraphFromGDLFile(const char *filepath, ida_flowgraph_t &out) {
  std::unordered_map<std::string, ida_flowgraph_node_t> title_node_map;

  auto on_node = [&](const std::string &title_text,
                     const std::string &label_text) -> void {
    ida_flowgraph_node_t node = boost::add_vertex(out);

    std::string s;
    if (title_text == "0") {
      //
      // try to get address from filename, since IDA may have just printed a
      // symbol
      //
      s = filepath;

      {
        std::string::size_type slash = s.rfind('/');
        if (slash != std::string::npos)
          s = s.substr(slash + 1); /* chop off leading directories */
      }

      if (s.size() > 2 &&
          s[0] == '0' &&
          s[1] == 'x') {
        s = s.substr(2); /* chop off prefix */
      }

      if (s.size() > 4 &&
          s[s.size() - 1] == 'l' &&
          s[s.size() - 2] == 'd' &&
          s[s.size() - 3] == 'g' &&
          s[s.size() - 4] == '.') {
        s = s.substr(0, s.size() - 4); /* chop off extension */
      }
    } else {
      //
      // get address from label
      //
      s = label_text;

      {
        std::string::size_type colon = s.find(':');
        if (colon != std::string::npos)
          s = s.substr(0, colon); /* chop off trailing asm  */
      }

      if (s.size() > 3 &&
          s[0] == '\f' &&
          isdigit(s[1]) &&
          isdigit(s[2]))
        s = s.substr(3); /* chop off weird prefix */

      if (s.size() > 3 &&
          s[s.size() - 3] == '\f' &&
          isdigit(s[s.size() - 2]) &&
          isdigit(s[s.size() - 1]))
        s = s.substr(0, s.size() - 3); /* chop off weird suffix */

      if (s.size() > 4 &&
          s[0] == 'l' &&
          s[1] == 'o' &&
          s[2] == 'c' &&
          s[3] == '_')
        s = s.substr(4); /* chop off prefix */

      if (s.size() > 7 &&
          s[0] == 'l' &&
          s[1] == 'o' &&
          s[2] == 'c' &&
          s[3] == 'r' &&
          s[4] == 'e' &&
          s[5] == 't' &&
          s[6] == '_')
        s = s.substr(7); /* chop off prefix */

      if (s.size() > 4 &&
          s[0] == 's' &&
          s[1] == 'u' &&
          s[2] == 'b' &&
          s[3] == '_')
        s = s.substr(4); /* chop off prefix */

      if (s.size() > 4 &&
          s[0] == 'd' &&
          s[1] == 'e' &&
          s[2] == 'f' &&
          s[3] == '_')
        s = s.substr(4); /* chop off prefix */
    }

    bool is_hexaddr = std::all_of(s.begin(), s.end(), ::isxdigit);

    uint64_t start_ea = ~0UL;
    if (is_hexaddr) {
      errno = 0;
      start_ea = strtol(s.c_str(), nullptr, 16);
      assert(errno == 0);
    }

    out[node].start_ea = start_ea;
    out[node].label = label_text;

    title_node_map[title_text] = node;
  };

  auto on_edge = [&](const std::string &source_text, const std::string &target_text) -> void {
    if (title_node_map.find(source_text) == title_node_map.end())
      throw std::runtime_error("on_edge: unknown source node " + source_text);

    if (title_node_map.find(target_text) == title_node_map.end())
      throw std::runtime_error("on_edge: unknown target node " + target_text);

    ida_flowgraph_node_t source = title_node_map[source_text];
    ida_flowgraph_node_t target = title_node_map[target_text];

    boost::add_edge(source, target, out);
  };

  std::string str(read_file_into_string(filepath));
  boost::erase_all(str, "\\\""); /* XXX */

  std::list<token_info_t> tokl;

  gdl_tokens<lex::lexertl::lexer<> > gdl_parser_functor;

  using boost::placeholders::_1;
  char const* first = str.c_str();
  char const* last = &first[str.size()];
  bool r = lex::tokenize(first, last, gdl_parser_functor, 
      boost::bind(on_token(), _1, boost::ref(tokl)));

  //
  // parse it out
  //
  auto tok_it = tokl.begin();

  auto next_token = [&](void) -> enum token_id {
    assert(tok_it != tokl.end());
    enum token_id res = (*tok_it).id;

    ++tok_it;

    return res;
  };

  auto current_token = [&](void) -> enum token_id {
    assert(tok_it != tokl.end());
    return (*tok_it).id;
  };

  unsigned line = 1;

  auto consume_token = [&](enum token_id id) -> token_info_t & {
    assert(tok_it != tokl.end());
    token_info_t &info = *tok_it++;

    if (info.id != id)
      throw std::runtime_error("line " + std::to_string(line) +
                               ": unexpected token id " + std::to_string(info.id) +
                               ", expected " + std::to_string(id));

    return info;
  };

  consume_token(ID_GRAPH);
  consume_token(ID_COLON);
  consume_token(ID_LEFT_BRACE);
  consume_token(ID_EOL);

  ++line;

  // line-by-line
  while (tok_it != tokl.end()) {
    const enum token_id id = next_token();

    switch (id) {
    case ID_TITLE:
      consume_token(ID_COLON);
      consume_token(ID_STR_CONST);
      break;

    case ID_MANHATTAN_EDGES:
    case ID_LAYOUTALGORITHM:
    case ID_FINETUNING:
    case ID_LAYOUT_DOWNFACTOR:
    case ID_LAYOUT_UPFACTOR:
    case ID_LAYOUT_NEARFACTOR:
    case ID_XLSPACE:
    case ID_YSPACE:
      consume_token(ID_COLON);
      next_token(); /* skip */
      break;

    case ID_COMMENT:
      break;

    case ID_COLORENTRY:
      consume_token(ID_INT_CONST);
      consume_token(ID_COLON);
      consume_token(ID_INT_CONST);
      consume_token(ID_INT_CONST);
      consume_token(ID_INT_CONST);
      break;

    case ID_NODE: {
      consume_token(ID_COLON);
      consume_token(ID_LEFT_BRACE);
      consume_token(ID_TITLE);
      consume_token(ID_COLON);
      const std::string &title_text = consume_token(ID_STR_CONST)._str_const.text;

      consume_token(ID_LABEL);
      consume_token(ID_COLON);
      const std::string &label_text = consume_token(ID_STR_CONST)._str_const.text;

      on_node(title_text, label_text);

      line += boost::count(label_text, '\n');

check_vertical_order:
      if (current_token() == ID_VERTICAL_ORDER) {
        next_token();
        consume_token(ID_COLON);
        consume_token(ID_INT_CONST);

        goto check_vertical_order; /* could be another */
      }

      if (current_token() == ID_COLOR) {
        next_token();
        consume_token(ID_COLON);
        next_token(); /* skip */
      }

      consume_token(ID_RIGHT_BRACE);
      break;
    }

    case ID_EDGE: {
      consume_token(ID_COLON);
      consume_token(ID_LEFT_BRACE);
      consume_token(ID_SOURCENAME);
      consume_token(ID_COLON);
      const std::string &source_text = consume_token(ID_STR_CONST)._str_const.text;
      consume_token(ID_TARGETNAME);
      consume_token(ID_COLON);
      const std::string &target_text = consume_token(ID_STR_CONST)._str_const.text;

      on_edge(source_text, target_text);

      if (current_token() == ID_LABEL) {
        next_token();
        consume_token(ID_COLON);
        const std::string &label_text = consume_token(ID_STR_CONST)._str_const.text;
        consume_token(ID_COLOR);
        consume_token(ID_COLON);
        next_token(); /* skip */
      }

      consume_token(ID_RIGHT_BRACE);
      break;
    }

    case ID_RIGHT_BRACE:
      return r; /* EOF */

    default:
      throw std::runtime_error("line " + std::to_string(line) + ": unhandled token " + std::to_string(id));
    }

    consume_token(ID_EOL);
    ++line;
  }

  return r;
}

}
