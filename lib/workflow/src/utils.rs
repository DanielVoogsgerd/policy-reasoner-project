//  UTILS.rs
//    by Lut99
//
//  Created:
//    02 Nov 2023, 15:11:34
//  Last edited:
//    16 Jan 2024, 15:01:05
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines some utilities used in multiple places in this crate.
//

use std::collections::HashSet;

use brane_ast::ast;
use brane_exe::pc::ProgramCounter;

use crate::{Elem, ElemTask, ElemCommit, ElemBranch, ElemParallel, ElemLoop, Dataset};

/***** LIBRARY FUNCTIONS *****/
/// Gets a workflow edge from a PC.
///
/// # Arguments
/// - `wir`: The [`ast::Workflow`] to get the edge from.
/// - `pc`: The program counter that points to the edge (hopefully).
///
/// # Returns
/// The edge the `pc` pointed to, or [`None`] if it was out-of-bounds.
#[inline]
pub fn get_edge(wir: &ast::Workflow, pc: ProgramCounter) -> Option<&ast::Edge> {
    if pc.func_id.is_main() {
        wir.graph.get(pc.edge_idx)
    } else {
        wir.funcs.get(&pc.func_id.id()).map(|edges| edges.get(pc.edge_idx)).flatten()
    }
}

/// A definition of a visitor for Workflow graphs
pub trait WorkflowVisitor {
    fn visit_task(&mut self, _task: &ElemTask){}
    fn visit_commit(&mut self, _commit: &ElemCommit){}
    fn visit_branch(&mut self, _branch: &ElemBranch){}
    fn visit_parallel(&mut self, _parallel: &ElemParallel){}
    fn visit_loop(&mut self, _loop: &ElemLoop){}
    fn visit_next(&mut self){}
    fn visit_stop(&mut self, _stop: &HashSet<Dataset>){}
}

/// A walker that visits all [`Elem`]s in preorder
pub fn walk_workflow_preorder(elem: &Elem, visitor: &mut impl WorkflowVisitor) {
    match elem {
        Elem::Task(task) => {
            visitor.visit_task(task);
            walk_workflow_preorder(&task.next, visitor);
        },
        Elem::Commit(commit) => {
            visitor.visit_commit(commit);
            walk_workflow_preorder(&commit.next, visitor);
        },
        Elem::Branch(branch) => {
            visitor.visit_branch(branch);
            for elem in &branch.branches {
                walk_workflow_preorder(elem, visitor);
            }

            walk_workflow_preorder(&branch.next, visitor);
        },
        Elem::Parallel(parallel) => {
            visitor.visit_parallel(parallel);
            for elem in &parallel.branches {
                walk_workflow_preorder(elem, visitor);
            }

            walk_workflow_preorder(&parallel.next, visitor);
        },
        Elem::Loop(r#loop) => {
            visitor.visit_loop(r#loop);
            walk_workflow_preorder(&r#loop.body, visitor);
            walk_workflow_preorder(&r#loop.next, visitor);
        },
        Elem::Next => {
            visitor.visit_next();
        },
        Elem::Stop(stop) => {
            visitor.visit_stop(stop);
        },
    }
}
