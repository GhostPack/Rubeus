using System.Collections.Generic;

namespace Rubeus.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}