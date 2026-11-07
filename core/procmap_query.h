#pragma once

struct procmap_query;

namespace jove {
namespace ProcMapQuery {

int get(int fd, struct procmap_query &);

}
}
