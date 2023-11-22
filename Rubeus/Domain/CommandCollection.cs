using System;
using System.Collections.Generic;
using Rubeus.Commands;

namespace Rubeus.Domain
{
    public class CommandCollection
    {
        private readonly Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();

        // How To Add A New Command:
        //  1. Create your command class in the Commands Folder
        //      a. That class must have a CommandName static property that has the Command's name
        //              and must also Implement the ICommand interface
        //      b. Put the code that does the work into the Execute() method
        //  2. Add an entry to the _availableCommands dictionary in the Constructor below.

        public CommandCollection()
        {
            _availableCommands.Add(Asktgs.CommandName, () => new Asktgs());
            _availableCommands.Add(Asktgt.CommandName, () => new Asktgt());
            _availableCommands.Add(Asreproast.CommandName, () => new Asreproast());
            _availableCommands.Add(Changepw.CommandName, () => new Changepw());
            _availableCommands.Add(Createnetonly.CommandName, () => new Createnetonly());
            _availableCommands.Add(Currentluid.CommandName, () => new Currentluid());
            _availableCommands.Add(Logonsession.CommandName, () => new Logonsession());
            _availableCommands.Add(Describe.CommandName, () => new Describe());
            _availableCommands.Add(Dump.CommandName, () => new Dump());
            _availableCommands.Add(Hash.CommandName, () => new Hash());
            _availableCommands.Add(HarvestCommand.CommandName, () => new HarvestCommand());
            _availableCommands.Add(Kerberoast.CommandName, () => new Kerberoast());
            _availableCommands.Add(Klist.CommandName, () => new Klist());
            _availableCommands.Add(Monitor.CommandName, () => new Monitor());
            _availableCommands.Add(Ptt.CommandName, () => new Ptt());
            _availableCommands.Add(Purge.CommandName, () => new Purge());
            _availableCommands.Add(RenewCommand.CommandName, () => new RenewCommand());
            _availableCommands.Add(S4u.CommandName, () => new S4u());
            _availableCommands.Add(Tgssub.CommandName, () => new Tgssub());
            _availableCommands.Add(Tgtdeleg.CommandName, () => new Tgtdeleg());
            _availableCommands.Add(Triage.CommandName, () => new Triage());
            _availableCommands.Add(Brute.CommandName, () => new Brute());
            // alias 'spray' to 'brute'
            _availableCommands.Add("spray", () => new Brute());
            _availableCommands.Add(Silver.CommandName, () => new Silver());
            _availableCommands.Add(Golden.CommandName, () => new Golden());
            _availableCommands.Add(Diamond.CommandName, () => new Diamond());
            _availableCommands.Add(Preauthscan.CommandName, () => new Preauthscan());
            _availableCommands.Add(ASREP2Kirbi.CommandName, () => new ASREP2Kirbi());
            _availableCommands.Add(Kirbi.CommandName, () => new Kirbi());
        }

        public bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            bool commandWasFound;

            if (string.IsNullOrEmpty(commandName) || _availableCommands.ContainsKey(commandName) == false)
                commandWasFound= false;
            else
            {
                // Create the command object 
                var command = _availableCommands[commandName].Invoke();
                
                // and execute it with the arguments from the command line
                command.Execute(arguments);

                commandWasFound = true;
            }

            return commandWasFound;
        }
    }
}