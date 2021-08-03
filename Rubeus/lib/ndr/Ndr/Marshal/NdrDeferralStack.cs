//  Copyright 2019 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using System;
using System.Collections.Generic;

namespace Rubeus.Ndr.Marshal
{
    internal sealed class NdrDeferralStackEntry : IDisposable
    {
        private readonly Stack<List<Action>> _stack;
        private readonly List<Action> _list;

        void IDisposable.Dispose()
        {
            if (_stack == null)
            {
                return;
            }

            var list = _stack.Pop();
            System.Diagnostics.Debug.Assert(list == _list);
            System.Diagnostics.Debug.WriteLine($"Flushing {list.Count} queued entries");

            foreach (var a in list)
            {
                a();
            }
        }

        public NdrDeferralStackEntry(Stack<List<Action>> stack)
        {
            _stack = stack;
            _list = stack?.Peek();
        }
    }

    internal class NdrDeferralStack
    {
        private readonly Stack<List<Action>> _stack;

        public NdrDeferralStack()
        {
            _stack = new Stack<List<Action>>();
        }

        private NdrDeferralStackEntry Push(bool allocate)
        {
            if (allocate)
            {
                System.Diagnostics.Debug.WriteLine($"Pushing new queue entry Empty: {Empty}");
                _stack.Push(new List<Action>());
                return new NdrDeferralStackEntry(_stack);
            }
            return null;
        }

        public NdrDeferralStackEntry Push()
        {
            return Push(Empty);
        }

        public void Add(Action a)
        {
            Action deferral = () =>
            {
                using (var queue = Push(true))
                {
                    a();
                }
            };
            System.Diagnostics.Debug.Assert(!Empty);
            System.Diagnostics.Debug.WriteLine("Adding deferred entry");
            _stack.Peek().Add(deferral);
        }

        public bool Empty => _stack.Count == 0;
    }
}
